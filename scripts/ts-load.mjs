/** Tiny loader: transpile a TS module (and its relative TS imports) with the project's typescript. */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import vm from 'node:vm';

export function loadTs(entry, root) {
  const req = createRequire(path.join(root, 'package.json'));
  const ts = req('typescript');
  const cache = new Map();
  const load = (file) => {
    if (cache.has(file)) return cache.get(file).exports;
    const src = fs.readFileSync(file, 'utf8');
    const { outputText } = ts.transpileModule(src, {
      compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
      fileName: file,
    });
    const mod = { exports: {} };
    cache.set(file, mod);
    const localRequire = (spec) => {
      if (spec.startsWith('.')) {
        const base = path.resolve(path.dirname(file), spec);
        for (const c of [base + '.ts', base + '.tsx', base + '/index.ts']) if (fs.existsSync(c)) return load(c);
      }
      return req(spec);
    };
    vm.runInThisContext(`(function(module,exports,require){${outputText}\n})`, { filename: file })(mod, mod.exports, localRequire);
    return mod.exports;
  };
  return load(path.resolve(root, entry));
}
