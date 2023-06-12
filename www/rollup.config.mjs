import { wasm } from '@rollup/plugin-wasm';
import { nodeResolve } from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import json from "@rollup/plugin-json";
// import nodePolyfills from "rollup-plugin-polyfill-node";

export default {
  input: './index.js',
  // format: "iife",
  output: {
    dir: 'build',
    format: "es"
  },
  plugins: [
    // nodePolyfills(),
    wasm({
      targetEnv: "browser",
      maxFileSize: 10000000,
      publicPath: "/build/"
    }),
    {
      name: "remove-import-meta",
      resolveImportMeta: () => `""`
    },
    nodeResolve({
      preferBuiltins: false,
      mainFields: ["module", "jsnext:main", "browser"]
    }),
    commonjs(),
    json(),
  ]
};