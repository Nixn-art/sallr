process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = '';
const test = require('node:test');
const assert = require('node:assert/strict');
const { helpers } = require('../server');

test('rejects malformed resource identifiers', () => {
  assert.throws(() => helpers.parseId('1 OR 1=1'));
  assert.throws(() => helpers.parseId('0'));
  assert.equal(helpers.parseId('42'), 42);
});
test('rejects markup and oversized text', () => {
  assert.throws(() => helpers.plainText('<img src=x>', 'title', 160, true));
  assert.throws(() => helpers.plainText('x'.repeat(161), 'title', 160, true));
  assert.equal(helpers.plainText(' a safe title ', 'title', 160, true), 'a safe title');
});
test('only permits bounded image data URLs', () => {
  assert.throws(() => helpers.validateImage('https://example.test/a.png'));
  assert.equal(helpers.validateImage('data:image/png;base64,AA=='), 'data:image/png;base64,AA==');
});
