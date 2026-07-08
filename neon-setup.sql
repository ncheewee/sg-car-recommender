-- ============================================================
-- SG Car Recommender — Neon setup (paste into Neon SQL Editor)
-- Read-public via anon role; writes gated by passphrase functions.
-- BEFORE RUNNING: change 'CHANGE-ME' below to your own passphrase.
-- ============================================================

-- 1. Tables ---------------------------------------------------
CREATE TABLE IF NOT EXISTS cars (
  id   text PRIMARY KEY,
  data jsonb NOT NULL,
  updated_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS scenarios (
  name text PRIMARY KEY,
  data jsonb NOT NULL,
  updated_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS overrides (
  car_id text PRIMARY KEY,
  data jsonb NOT NULL,
  updated_at timestamptz DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_settings (
  key text PRIMARY KEY,
  value text NOT NULL
);

-- 2. Passphrase (stored as SHA-256 hash) ----------------------
INSERT INTO app_settings (key, value)
VALUES ('pass_hash', encode(sha256('CHANGE-ME'::bytea), 'hex'))
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

-- 3. Write functions (SECURITY DEFINER, passphrase-checked) ---
CREATE OR REPLACE FUNCTION check_pass(p_pass text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER AS $$
  SELECT encode(sha256(p_pass::bytea), 'hex') =
         (SELECT value FROM app_settings WHERE key = 'pass_hash');
$$;

CREATE OR REPLACE FUNCTION save_scenario(p_pass text, p_name text, p_data jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT check_pass(p_pass) THEN RAISE EXCEPTION 'bad passphrase'; END IF;
  INSERT INTO scenarios (name, data) VALUES (p_name, p_data)
  ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data, updated_at = now();
END $$;

CREATE OR REPLACE FUNCTION save_override(p_pass text, p_car text, p_data jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT check_pass(p_pass) THEN RAISE EXCEPTION 'bad passphrase'; END IF;
  IF p_data = '{}'::jsonb THEN
    DELETE FROM overrides WHERE car_id = p_car;
  ELSE
    INSERT INTO overrides (car_id, data) VALUES (p_car, p_data)
    ON CONFLICT (car_id) DO UPDATE SET data = EXCLUDED.data, updated_at = now();
  END IF;
END $$;

CREATE OR REPLACE FUNCTION save_car(p_pass text, p_data jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  IF NOT check_pass(p_pass) THEN RAISE EXCEPTION 'bad passphrase'; END IF;
  INSERT INTO cars (id, data) VALUES (p_data->>'id', p_data)
  ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now();
END $$;

-- 4. Anonymous role: read-only + execute save functions -------
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anonymous') THEN
    CREATE ROLE anonymous NOLOGIN;
  END IF;
END $$;
GRANT anonymous TO CURRENT_USER;
GRANT USAGE ON SCHEMA public TO anonymous;
GRANT SELECT ON cars, scenarios, overrides TO anonymous;
REVOKE ALL ON app_settings FROM anonymous;
GRANT EXECUTE ON FUNCTION save_scenario(text, text, jsonb) TO anonymous;
GRANT EXECUTE ON FUNCTION save_override(text, text, jsonb) TO anonymous;
GRANT EXECUTE ON FUNCTION save_car(text, jsonb) TO anonymous;
-- In the Neon console → Data API settings, set db_anon_role = 'anonymous'.

-- 5. Seed dataset (snapshot 8 Jul 2026) -----------------------
INSERT INTO cars (id, data) VALUES
('my',   '{"id":"my","name":"Tesla Model Y","trim":"RWD 110 (Cat A)","body":"suv","price":195999,"cat":"A","kw":110,"range":466,"eff":15.6,"rtax":1214,"ins":2450,"maint":600,"resale":52000,"rel":8.0,"feel":7.5,"space":8.5,"tech":9.5,"brand":8.0,"sent":8.1,"est":["ins","resale"],"note":"Cheapest energy+servicing in field; supercharger network; firm ride. EEAI ends 1 Jan 2027."}'),
('m3',   '{"id":"m3","name":"Tesla Model 3","trim":"RWD 110 (Cat A)","body":"sedan","price":179999,"cat":"A","kw":110,"range":513,"eff":13.6,"rtax":1214,"ins":2350,"maint":600,"resale":48000,"rel":8.0,"feel":8.0,"space":6.5,"tech":9.5,"brand":8.0,"sent":8.2,"est":["ins","resale"],"note":"Most efficient car here; sedan practicality trade-off."}'),
('atto', '{"id":"atto","name":"BYD Atto 3","trim":"Dynamic (Cat A)","body":"suv","price":165888,"cat":"A","kw":110,"range":420,"eff":16.0,"rtax":1214,"ins":2250,"maint":800,"resale":38000,"rel":7.5,"feel":6.0,"space":7.5,"tech":7.0,"brand":6.5,"sent":7.2,"est":["price","ins","resale"],"note":"Value pick; huge SG service network; soft drive."}'),
('seal', '{"id":"seal","name":"BYD Seal","trim":"Premium (Cat B)","body":"sedan","price":208888,"cat":"B","kw":230,"range":570,"eff":16.5,"rtax":2178,"ins":2600,"maint":800,"resale":46000,"rel":7.5,"feel":8.5,"space":7.0,"tech":7.5,"brand":6.5,"sent":7.9,"est":["price","ins","resale"],"note":"Best driver’s BYD; Cat B COE + road tax bites."}'),
('sl7',  '{"id":"sl7","name":"BYD Sealion 7","trim":"Premium (Cat B)","body":"suv","price":215888,"cat":"B","kw":230,"range":482,"eff":18.2,"rtax":2178,"ins":2700,"maint":800,"resale":50000,"rel":7.5,"feel":7.5,"space":8.5,"tech":7.5,"brand":6.5,"sent":7.7,"est":["price","ins","resale"],"note":"Plush family SUV; thirstier per km than Model Y."}'),
('g6a',  '{"id":"g6a","name":"Xpeng G6","trim":"Air / std RWD (Cat A)","body":"suv","price":209999,"cat":"A","kw":190,"range":435,"eff":17.5,"rtax":1850,"ins":2550,"maint":750,"resale":44000,"rel":7.0,"feel":7.5,"space":8.0,"tech":8.5,"brand":6.0,"sent":7.8,"est":["price","rtax","ins","resale"],"note":"800V fast charging; XNGP ADAS strong; young SG dealer network."}'),
('g6p',  '{"id":"g6p","name":"Xpeng G6","trim":"Pro (Cat B)","body":"suv","price":218999,"cat":"B","kw":210,"range":500,"eff":17.8,"rtax":2050,"ins":2650,"maint":750,"resale":46000,"rel":7.0,"feel":7.8,"space":8.0,"tech":8.8,"brand":6.0,"sent":7.8,"est":["rtax","ins","resale"],"note":"More range + power than Air; is Cat B premium worth it?"}'),
('aiv',  '{"id":"aiv","name":"GAC Aion V","trim":"Premium (Cat A)","body":"suv","price":166988,"cat":"A","kw":150,"range":510,"eff":16.8,"rtax":1500,"ins":2350,"maint":750,"resale":36000,"rel":7.0,"feel":6.5,"space":8.5,"tech":7.0,"brand":5.5,"sent":7.4,"est":["rtax","ins","resale"],"note":"Cheapest entry; cavernous rear; resale unproven."}'),
('hht',  '{"id":"hht","name":"Hyptec HT","trim":"Premium (Cat B)","body":"suv","price":226988,"cat":"B","kw":250,"range":520,"eff":17.2,"rtax":2300,"ins":2750,"maint":800,"resale":48000,"rel":7.0,"feel":7.0,"space":9.0,"tech":8.0,"brand":5.5,"sent":7.3,"est":["rtax","ins","resale"],"note":"Lounge cabin, gullwing option; heaviest + priciest of Chinese set."}'),
('keep', '{"id":"keep","name":"Renew 216d COE","trim":"Keep F46 · 10-yr PQP","body":"suv","price":124705,"cat":"B","kw":85,"range":0,"eff":4.6,"rtax":1550,"ins":1800,"maint":2600,"resale":4000,"rel":5.5,"feel":6.0,"space":8.0,"tech":3.5,"brand":6.5,"sent":6.0,"isKeep":true,"est":["maint"],"note":"Known quantity, zero shopping cost. 10-yr-old diesel, rising maintenance, no warranty. 5-yr PQP ≈ $62,353."}')
ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, updated_at = now();
