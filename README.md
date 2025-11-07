# Cipher312

A WebAssembly library for working with the trinary cipher used by the mysterious Youtube channel/ARG [3121534312](https://www.youtube.com/@3121534312). Built on top of WIT (WebAssembly Interface Types).

[![](https://img.youtube.com/vi/VGK3Ag06VaU/0.jpg)](https://www.youtube.com/watch?v=VGK3Ag06VaU)

For more context (god knows you'll need it) check out this really well-made video that goes into way more detail:

[Youtube's oldest unsolved mystery](https://www.youtube.com/watch?v=TRD3OrCJJ9o)

[![Youtube's oldest unsolved mystery](https://img.youtube.com/vi/TRD3OrCJJ9o/0.jpg)](https://www.youtube.com/watch?v=TRD3OrCJJ9o)

Most of the decoding logic is based on the work already done by people who put in much more effort [here](https://docs.google.com/presentation/d/110bIi0N-z-D4FKMVwkCpnr1YUTwLF7zX79gop2ZVmQo/present?slide=id.g38bd95b3ca2_24_0).

### Usage

You can install the library directly if you're using Rust:

```rs
use cipher312::{Codec, NormalizedCiphertext};

fn main() {
    let normalized = NormalizedCiphertext::new("1321521321353");

    let decoded = Codec::decode(normalized).unwrap();

    println!("{}", decoded.to_string());
    // hello
}
```

The beauty of webassembly is you can use it with any language that supports WASM (and WIT in this case). There are some examples in the [consumers](./consumers) directory for webassembly support for different languages.

#### Javascript

```shell
# in your project directory
curl -Lo cipher312.wasm https://github.com/xetera/cipher312/releases/latest/download/cipher312.wasm
npx jco transpile cipher312.wasm -o dist
```

```js
import { codec } from "./dist/cipher312.js";

let normalized = new codec.NormalizedCiphertext(
  "2656161216521504321315412641524315012443124104412345326231312165352",
);

let decoded = codec.decode(normalized);

console.log(decoded.get());
// ROUTINE CLEARANCE DATA ABSORPTION
```
