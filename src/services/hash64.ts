/** Two independent 32-bit hashes → one 64-bit key (as a pair). Used for the compact bundled blocklist. */
export function h64(s: string): [number, number] {
  let a = 0x811c9dc5, b = 0x12345678;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    a = Math.imul(a ^ c, 0x01000193) >>> 0;
    b = (Math.imul(b, 31) + c + (b >>> 13)) >>> 0;
    b = Math.imul(b ^ (b >>> 16), 0x45d9f3b) >>> 0;
  }
  return [a >>> 0, b >>> 0];
}
