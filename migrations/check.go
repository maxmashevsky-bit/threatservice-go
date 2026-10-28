package migrations

import (
	"context"
	"fmt"
	"slices"
)

type column struct {
	name, sqlType, defaultSQL string
}

// The ledger is not a substitute for checking the objects the service actually
// uses. Fail closed on schema drift; never repair or delete operator data here.
func checkSchema(ctx context.Context, q querier) error {
	ledger := []column{{"version", "bigint", ""}, {"applied_at", "timestamp with time zone", "CURRENT_TIMESTAMP"}}
	if _, err := checkTable(ctx, q, "schema_migrations", ledger); err != nil {
		return err
	}
	columns := []column{
		{"md5", "character varying(32)", ""},
		{"name", "character varying(255)", ""},
		{"description", "text", "''::text"},
		{"severity", "character varying(8)", "'unknown'::character varying"},
		{"created_at", "timestamp with time zone", "CURRENT_TIMESTAMP"},
		{"updated_at", "timestamp with time zone", "CURRENT_TIMESTAMP"},
	}
	oid, err := checkTable(ctx, q, "threats", columns)
	if err != nil {
		return err
	}
	var validKey, canRead, canInsert, canUpdate, validCollation, hasTriggers bool
	err = q.QueryRow(ctx, `SELECT
		EXISTS (SELECT 1 FROM pg_catalog.pg_index i
		 WHERE i.indrelid = $1 AND i.indisprimary AND i.indisvalid AND i.indisready
		 AND i.indnatts = 1 AND i.indkey::text = '1'),
		pg_catalog.has_table_privilege($1, 'SELECT'),
		pg_catalog.has_table_privilege($1, 'INSERT'),
		pg_catalog.has_table_privilege($1, 'UPDATE'),
		EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a
		 JOIN pg_catalog.pg_collation c ON c.oid = a.attcollation
		 JOIN pg_catalog.pg_namespace n ON n.oid = c.collnamespace
		 WHERE a.attrelid = $1 AND a.attname = 'md5' AND c.collname = 'C' AND n.nspname = 'pg_catalog'),
		EXISTS (SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid = $1 AND NOT tgisinternal)`, oid).
		Scan(&validKey, &canRead, &canInsert, &canUpdate, &validCollation, &hasTriggers)
	if err != nil {
		return fmt.Errorf("inspect threat constraints and privileges: %w", err)
	}
	if !validKey || !validCollation || hasTriggers {
		return fmt.Errorf("threats primary key, MD5 collation or triggers differ from migration version %d", Version)
	}
	if !canRead || !canInsert || !canUpdate {
		return fmt.Errorf("current role requires SELECT, INSERT and UPDATE on threats")
	}
	// Check their identity, validation state and referenced columns, rather than
	// comparing PostgreSQL's version-dependent pretty-printed SQL text.
	expected := map[string][]int16{
		"threats_md5_format":         {1},
		"threats_name_length":        {2},
		"threats_name_not_blank":     {2},
		"threats_description_length": {3},
		"threats_severity_values":    {4},
		"threats_timestamp_order":    {5, 6},
	}
	rows, err := q.Query(ctx, `SELECT conname, conkey, convalidated
		FROM pg_catalog.pg_constraint WHERE conrelid = $1 AND contype = 'c'`, oid)
	if err != nil {
		return fmt.Errorf("inspect threat checks: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		var keys []int16
		var validated bool
		if err := rows.Scan(&name, &keys, &validated); err != nil {
			return fmt.Errorf("read threat check: %w", err)
		}
		want, ok := expected[name]
		slices.Sort(keys)
		if !ok || !validated || !slices.Equal(keys, want) {
			return fmt.Errorf("constraint %s differs from migration version %d", name, Version)
		}
		delete(expected, name)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read threat checks: %w", err)
	}
	if len(expected) != 0 {
		return fmt.Errorf("threats is missing required check constraints")
	}
	return nil
}

func checkTable(ctx context.Context, q querier, name string, expected []column) (uint32, error) {
	var oid uint32
	var kind, persistence string
	var rls bool
	err := q.QueryRow(ctx, `SELECT c.oid, c.relkind::text, c.relpersistence::text, c.relrowsecurity
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = pg_catalog.current_schema() AND c.relname = $1`, name).
		Scan(&oid, &kind, &persistence, &rls)
	if err != nil {
		return 0, fmt.Errorf("find %s in the target schema: %w", name, err)
	}
	if kind != "r" || persistence != "p" || rls {
		return 0, fmt.Errorf("%s must be a permanent ordinary table without row-level security", name)
	}
	rows, err := q.Query(ctx, `SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
		a.attnotnull, COALESCE(pg_catalog.pg_get_expr(d.adbin, d.adrelid), '')
		FROM pg_catalog.pg_attribute a
		LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
		WHERE a.attrelid = $1 AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`, oid)
	if err != nil {
		return 0, fmt.Errorf("inspect %s columns: %w", name, err)
	}
	defer rows.Close()
	i := 0
	for rows.Next() {
		var actual column
		var notNull bool
		if err := rows.Scan(&actual.name, &actual.sqlType, &notNull, &actual.defaultSQL); err != nil {
			return 0, fmt.Errorf("read %s columns: %w", name, err)
		}
		if i >= len(expected) || actual != expected[i] || !notNull {
			return 0, fmt.Errorf("%s columns differ from migration version %d", name, Version)
		}
		i++
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("read %s columns: %w", name, err)
	}
	if i != len(expected) {
		return 0, fmt.Errorf("%s is missing required columns", name)
	}
	return oid, nil
}
