const fs = require('fs');
const path = require('path');

const svgPath = path.join(__dirname, '../apps/client/src/components/world-map.svg');
const content = fs.readFileSync(svgPath, 'utf8');

// Simple regex parser to extract paths and groups
// We want to transform each <path id="XXX" d="YYY" /> to Vue-friendly syntax
// We also want to support <g id="XXX"> with nested paths

let parsedPaths = [];

// Match simple paths
const pathRegex = /<path\s+id="([^"]+)"\s+d="([^"]+)"[^/>]*\/>/g;
let match;
while ((match = pathRegex.exec(content)) !== null) {
  const id = match[1];
  const d = match[2];
  parsedPaths.push({ id, d, group: null });
}

// Match groups containing paths
const groupRegex = /<g\s+id="([^"]+)">([\s\S]*?)<\/g>/g;
let groupMatch;
while ((groupMatch = groupRegex.exec(content)) !== null) {
  const groupId = groupMatch[1];
  const groupContent = groupMatch[2];
  const nestedPathRegex = /<path[^>]*d="([^"]+)"[^/>]*\/>/g;
  let nestedMatch;
  let subIndex = 0;
  while ((nestedMatch = nestedPathRegex.exec(groupContent)) !== null) {
    const d = nestedMatch[1];
    parsedPaths.push({ id: groupId + '_' + subIndex, d, group: groupId });
    subIndex++;
  }
}

console.log(`Parsed ${parsedPaths.length} path elements.`);

// Output Vue template representation
let output = '';
parsedPaths.forEach(p => {
  const regionId = p.group || p.id;
  output += `      <path
        id="${p.id}"
        d="${p.d}"
        :class="[
          'transition-all duration-300 stroke-[#18181b]/30 hover:fill-accent-blue/30 cursor-pointer',
          getRegionClass('${regionId}'),
          selectedRegion === getRegionOfCountry('${regionId}') ? 'fill-accent-blue/20 stroke-accent-blue/50' : 'fill-bg-tertiary/10'
        ]"
        stroke-width="0.5"
        @click="handleCountryClick('${regionId}')"
      />\n`;
});

fs.writeFileSync(path.join(__dirname, 'parsed_paths.txt'), output);
console.log('Saved parsed paths to parsed_paths.txt');
