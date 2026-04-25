#!/usr/bin/env node
import { build } from "esbuild";
import { execSync } from "node:child_process";
import { readFileSync, mkdirSync, writeFileSync } from "fs";

const pkg = JSON.parse(readFileSync("package.json", "utf8"));

mkdirSync("dist", { recursive: true });

const entries = {
  index: { platform: "neutral", external: [] },
  nextjs: { platform: "neutral", external: ["next", "next/*"] },
  express: { platform: "node", external: ["node:http", "node:stream"] },
  fastify: { platform: "node", external: ["node:http", "node:stream", "fastify"] },
  lambda: { platform: "node", external: [] },
};

for (const [name, opts] of Object.entries(entries)) {
  const result = await build({
    entryPoints: [`src/${name}.ts`],
    bundle: true,
    format: "esm",
    platform: opts.platform,
    target: "es2022",
    minify: true,
    write: false,
    treeShaking: true,
    legalComments: "none",
    external: opts.external,
    define: { "__OBFIOUS_VERSION__": JSON.stringify(pkg.version) },
  });

  writeFileSync(`dist/${name}.js`, result.outputFiles[0].text);
  console.log(`  ${name}.js (${result.outputFiles[0].text.length} bytes)`);
}

// --- Type declarations (generated from source by tsc) ---

console.log("Generating type declarations...");
execSync("npx tsc -p tsconfig.build.json", { stdio: "inherit" });

console.log("@obfious/js built successfully");
