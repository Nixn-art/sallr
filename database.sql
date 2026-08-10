CREATE TABLE users (
  id SERIAL PRIMARY KEY, username VARCHAR(40) UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  avatar_url TEXT, whatsapp VARCHAR(25), deleted_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE listings (
  id SERIAL PRIMARY KEY, seller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  title VARCHAR(160) NOT NULL, price_zmw NUMERIC(10,2) NOT NULL, description TEXT,
  category VARCHAR(40) NOT NULL, color VARCHAR(40), size VARCHAR(20), images JSONB NOT NULL DEFAULT '[]',
  sold BOOLEAN DEFAULT FALSE, buyer_id INTEGER REFERENCES users(id) ON DELETE SET NULL, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE favorites (
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  listing_id INTEGER REFERENCES listings(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(), PRIMARY KEY (user_id, listing_id)
);
CREATE TABLE reviews (
  id SERIAL PRIMARY KEY, seller_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  reviewer_id INTEGER REFERENCES users(id) ON DELETE SET NULL, stars SMALLINT CHECK(stars BETWEEN 1 AND 5), body TEXT, created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE messages (
  id SERIAL PRIMARY KEY, sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE, listing_id INTEGER REFERENCES listings(id) ON DELETE SET NULL, body TEXT NOT NULL, read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE audit_events (
  id BIGSERIAL PRIMARY KEY, actor_id INTEGER, action VARCHAR(80) NOT NULL,
  resource_type VARCHAR(80), resource_id VARCHAR(80), result VARCHAR(20) NOT NULL DEFAULT 'success',
  request_id UUID NOT NULL, metadata JSONB NOT NULL DEFAULT '{}', created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE revoked_tokens (jti UUID PRIMARY KEY, expires_at TIMESTAMPTZ NOT NULL);
CREATE INDEX listings_seller_created_idx ON listings(seller_id, created_at DESC);
CREATE INDEX messages_participants_created_idx ON messages(sender_id, recipient_id, created_at DESC);
CREATE INDEX audit_events_created_idx ON audit_events(created_at);
CREATE INDEX revoked_tokens_expiry_idx ON revoked_tokens(expires_at);
CREATE UNIQUE INDEX users_username_lower_unique ON users (LOWER(username)) WHERE deleted_at IS NULL;
