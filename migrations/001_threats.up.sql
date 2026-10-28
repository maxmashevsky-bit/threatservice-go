CREATE TABLE threats (
    md5 varchar(32) COLLATE "C" PRIMARY KEY,
    name varchar(255) NOT NULL,
    description text NOT NULL DEFAULT '',
    severity varchar(8) NOT NULL DEFAULT 'unknown',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT threats_md5_format CHECK (md5 ~ '^[a-f0-9]{32}$'),
    CONSTRAINT threats_name_length CHECK (char_length(name) BETWEEN 1 AND 255),
    CONSTRAINT threats_name_not_blank CHECK (char_length(btrim(name)) > 0),
    CONSTRAINT threats_description_length CHECK (char_length(description) <= 4000),
    CONSTRAINT threats_severity_values
        CHECK (severity IN ('unknown', 'low', 'medium', 'high', 'critical')),
    CONSTRAINT threats_timestamp_order CHECK (updated_at >= created_at)
);
