const arr = new Uint8Array(50);
crypto.getRandomValues(arr);
// eslint-disable-next-line no-console
console.log(Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join(""));