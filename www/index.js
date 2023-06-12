import * as anoncreds from "wasm-pkg";
import wasm from "wasm-pkg/anoncreds_bg.wasm";

(async () => {
  await anoncreds.default(wasm());

  window.anoncreds = anoncreds;
  window.wasm = anoncreds;
  console.log("READY");
})()
