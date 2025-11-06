import { codec } from "./dist/cipher312.js";

let normalized = new codec.NormalizedCiphertext(
  "2656161216521504321315412641524315012443124104412345326231312165352",
);

let decoded = codec.decode(normalized);

console.log(decoded.getCodepoints());
