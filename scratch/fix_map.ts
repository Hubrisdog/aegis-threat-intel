import { readFileSync, writeFileSync } from 'fs';

const filePath = 'apps/client/src/components/ThreatMap.vue';
console.log('Reading:', filePath);
let content = readFileSync(filePath, 'utf8');

// Replace the class arrays of the SVG paths
// Old:
// :class="[
//   'transition-all duration-300 stroke-[#18181b]/30 hover:fill-accent-blue/30 cursor-pointer',
//   getRegionClass('xxx'),
//   selectedRegion === getRegionOfCountry('xxx') ? 'fill-accent-blue/20 stroke-accent-blue/50' : 'fill-bg-tertiary/10'
// ]"
// New:
// :class="[
//   'transition-all duration-300 stroke-[#38bdf8]/20 hover:fill-accent-blue/30 cursor-pointer',
//   selectedRegion === getRegionOfCountry('xxx') ? 'fill-accent-blue/25 stroke-accent-blue/60' : getRegionClass('xxx')
// ]"

const regex = /:class="\[\s*'transition-all duration-300 stroke-\[#18181b\]\/30 hover:fill-accent-blue\/30 cursor-pointer',\s*getRegionClass\('([^']+)'\),\s*selectedRegion === getRegionOfCountry\('([^']+)'\) \? 'fill-accent-blue\/20 stroke-accent-blue\/50' : 'fill-bg-tertiary\/10'\s*\]"/g;

const matchCount = (content.match(regex) || []).length;
console.log(`Found ${matchCount} matches to replace.`);

content = content.replace(regex, (match, p1, p2) => {
  return `:class="[
          'transition-all duration-300 stroke-[#38bdf8]/20 hover:fill-accent-blue/30 cursor-pointer',
          selectedRegion === getRegionOfCountry('${p1}') ? 'fill-accent-blue/25 stroke-accent-blue/60' : getRegionClass('${p1}')
        ]"`;
});

// Write modified contents back
writeFileSync(filePath, content, 'utf8');
console.log('Successfully updated ThreatMap.vue!');
