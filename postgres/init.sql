-- =============================================================
-- FreeRADIUS PostgreSQL Schema + Seed Data
-- =============================================================

-- Kullanıcı kimlik bilgileri
-- attribute: Cleartext-Password | MD5-Password | Crypt-Password
-- op:  ':=' = her zaman bu değeri ata, '==' = eşit mi kontrol et
CREATE TABLE IF NOT EXISTS radcheck (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        CHAR(2)      NOT NULL DEFAULT '==',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radcheck_username ON radcheck (username, attribute);

-- Kullanıcıya gönderilecek RADIUS reply atribütleri
CREATE TABLE IF NOT EXISTS radreply (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        CHAR(2)      NOT NULL DEFAULT '=',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radreply_username ON radreply (username, attribute);

-- Grup check atribütleri (gruba ek kısıtlamalar için)
CREATE TABLE IF NOT EXISTS radgroupcheck (
    id        SERIAL PRIMARY KEY,
    groupname VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        CHAR(2)      NOT NULL DEFAULT '==',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radgroupcheck_groupname ON radgroupcheck (groupname, attribute);

-- Gruba atanacak RADIUS reply atribütleri (VLAN burada)
CREATE TABLE IF NOT EXISTS radgroupreply (
    id        SERIAL PRIMARY KEY,
    groupname VARCHAR(64)  NOT NULL DEFAULT '',
    attribute VARCHAR(64)  NOT NULL DEFAULT '',
    op        CHAR(2)      NOT NULL DEFAULT '=',
    value     VARCHAR(253) NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS radgroupreply_groupname ON radgroupreply (groupname, attribute);

-- Kullanıcı → Grup eşleştirmesi
CREATE TABLE IF NOT EXISTS radusergroup (
    id        SERIAL PRIMARY KEY,
    username  VARCHAR(64) NOT NULL DEFAULT '',
    groupname VARCHAR(64) NOT NULL DEFAULT '',
    priority  INTEGER     NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS radusergroup_username ON radusergroup (username);

-- Accounting (oturum) kayıtları
CREATE TABLE IF NOT EXISTS radacct (
    radacctid       BIGSERIAL PRIMARY KEY,
    acctsessionid   VARCHAR(64)  NOT NULL DEFAULT '',
    acctuniqueid    VARCHAR(32)  NOT NULL DEFAULT '',
    username        VARCHAR(64)  NOT NULL DEFAULT '',
    nasipaddress    VARCHAR(15)  NOT NULL DEFAULT '',
    nasportid       VARCHAR(15),
    acctstarttime   TIMESTAMPTZ,
    acctupdatetime  TIMESTAMPTZ,
    acctstoptime    TIMESTAMPTZ,
    acctsessiontime INTEGER,
    acctinputoctets BIGINT       DEFAULT 0,
    acctoutputoctets BIGINT      DEFAULT 0,
    callingstationid VARCHAR(50) NOT NULL DEFAULT '',
    calledstationid  VARCHAR(50) NOT NULL DEFAULT '',
    acctterminatecause VARCHAR(32) NOT NULL DEFAULT '',
    framedipaddress  VARCHAR(15) NOT NULL DEFAULT '',
    acctstatustype   VARCHAR(32) DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS radacct_acctsessionid ON radacct (acctsessionid);
CREATE INDEX IF NOT EXISTS radacct_username ON radacct (username);
CREATE INDEX IF NOT EXISTS radacct_nasipaddress ON radacct (nasipaddress);

-- Post-auth log (başarılı/başarısız auth kayıtları)
CREATE TABLE IF NOT EXISTS radpostauth (
    id       BIGSERIAL PRIMARY KEY,
    username VARCHAR(64) NOT NULL DEFAULT '',
    pass     VARCHAR(64) NOT NULL DEFAULT '',
    reply    VARCHAR(32) NOT NULL DEFAULT '',
    authdate TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS radpostauth_username ON radpostauth (username);

-- =============================================================
-- SEED DATA
-- =============================================================
-- Parolalar MD5 ile hash'lenmiş (md5() PostgreSQL built-in fonksiyonu)
-- FreeRADIUS PAP auth: gelen plaintext'i MD5'ler, stored hash ile karşılaştırır
-- Üretim ortamında API üzerinden Crypt-Password (bcrypt) kullanılmalıdır

INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('admin',    'MD5-Password', ':=', md5('admin123')),
    ('employee', 'MD5-Password', ':=', md5('emp123')),
    ('guest',    'MD5-Password', ':=', md5('guest123'))
ON CONFLICT DO NOTHING;

-- VLAN Atamaları:
--   Tunnel-Type = 13 → VLAN
--   Tunnel-Medium-Type = 6 → IEEE 802
--   Tunnel-Private-Group-Id = VLAN ID
INSERT INTO radgroupreply (groupname, attribute, op, value) VALUES
    ('admin',    'Tunnel-Type',             ':=', '13'),
    ('admin',    'Tunnel-Medium-Type',      ':=', '6'),
    ('admin',    'Tunnel-Private-Group-Id', ':=', '10'),

    ('employee', 'Tunnel-Type',             ':=', '13'),
    ('employee', 'Tunnel-Medium-Type',      ':=', '6'),
    ('employee', 'Tunnel-Private-Group-Id', ':=', '20'),

    ('guest',    'Tunnel-Type',             ':=', '13'),
    ('guest',    'Tunnel-Medium-Type',      ':=', '6'),
    ('guest',    'Tunnel-Private-Group-Id', ':=', '30')
ON CONFLICT DO NOTHING;

-- Kullanıcı → Grup
INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('admin',    'admin',    1),
    ('employee', 'employee', 1),
    ('guest',    'guest',    1)
ON CONFLICT DO NOTHING;

-- MAB testi için bilinen MAC adresleri (örnek)
-- Yazıcı MAC → employee VLAN
INSERT INTO radcheck (username, attribute, op, value) VALUES
    ('aa:bb:cc:dd:ee:ff', 'Cleartext-Password', ':=', 'aa:bb:cc:dd:ee:ff')
ON CONFLICT DO NOTHING;

INSERT INTO radusergroup (username, groupname, priority) VALUES
    ('aa:bb:cc:dd:ee:ff', 'employee', 1)
ON CONFLICT DO NOTHING;
