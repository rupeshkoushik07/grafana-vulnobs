import { cp, mkdir } from 'node:fs/promises';

const source = new URL('../src/datasource/img/', import.meta.url);
const destination = new URL('../dist/datasource/img/', import.meta.url);

await mkdir(destination, { recursive: true });
await cp(source, destination, { recursive: true });
