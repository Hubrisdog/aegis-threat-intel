const fs = require('fs');
const path = require('path');

const parsedPathsPath = path.join(__dirname, 'parsed_paths.txt');
const parsedPaths = fs.readFileSync(parsedPathsPath, 'utf8');

const outputVuePath = path.join(__dirname, '../apps/client/src/components/ThreatMap.vue');

const vueTemplate = `<script setup lang="ts">
import { ref, computed } from 'vue';
import { Globe, MapPin, ListFilter } from 'lucide-vue-next';
import type { IOC } from '../types';

const props = defineProps<{
  iocs: IOC[];
}>();

const emit = defineEmits<{
  (e: 'filterCountry', countryCode: string): void;
}>();

interface RegionHub {
  id: string;
  name: string;
  x: number;
  y: number;
  countryCode: string;
}

// Centered on simple-world-map projection coordinates (viewBox: 30.767 241.591 784.077 458.627)
const REGION_HUBS: RegionHub[] = [
  { id: 'na', name: 'North America', x: 220, y: 390, countryCode: 'US' },
  { id: 'sa', name: 'South America', x: 320, y: 580, countryCode: 'BR' },
  { id: 'eu', name: 'Europe & UK', x: 440, y: 350, countryCode: 'EU' },
  { id: 'af', name: 'Africa & ME', x: 490, y: 510, countryCode: 'ZA' },
  { id: 'as', name: 'Asia Pacific', x: 640, y: 410, countryCode: 'CN' },
  { id: 'oc', name: 'Oceania', x: 710, y: 640, countryCode: 'AU' },
];

const selectedRegion = ref<string | null>(null);

const COUNTRY_TO_REGION: Record<string, string> = {
  // NA
  us: 'na', ca: 'na', mx: 'na', gl: 'na',
  // SA
  br: 'sa', ar: 'sa', cl: 'sa', co: 'sa', pe: 'sa', ve: 'sa', bo: 'sa', uy: 'sa', py: 'sa', ec: 'sa', gf: 'sa', sur: 'sa', gy: 'sa', pa: 'sa', cr: 'sa', ni: 'sa', hn: 'sa', sv: 'sa', gt: 'sa', bz: 'sa', jam: 'sa', cub: 'sa', ht: 'sa', dom: 'sa',
  // EU
  gb: 'eu', fr: 'eu', de: 'eu', it: 'eu', es: 'eu', pl: 'eu', ua: 'eu', ro: 'eu', by: 'eu', gr: 'eu', bg: 'eu', hu: 'eu', pt: 'eu', aut: 'eu', cz: 'eu', ie: 'eu', se: 'eu', no: 'eu', fi: 'eu', ee: 'eu', lv: 'eu', lt: 'eu', ch: 'eu', be: 'eu', nl: 'eu', dk: 'eu', is: 'eu',
  // AF & ME
  za: 'af', eg: 'af', ng: 'af', sa: 'af', ae: 'af', dz: 'af', ma: 'af', ly: 'af', sd: 'af', ke: 'af', et: 'af', so: 'af', somaliland: 'af', ye: 'af', om: 'af', iq: 'af', sy: 'af', jo: 'af', il: 'af', tr: 'af', ir: 'af', pk: 'af', af: 'af',
  // AS
  cn: 'as', in: 'as', jp: 'as', kr: 'as', kp: 'as', ru: 'as', kz: 'as', mn: 'as', tw: 'as', kh: 'as', vn: 'as', la: 'as', th: 'as', my: 'as', id: 'as', ph: 'as', bd: 'as', lk: 'as', np: 'as', mm: 'as',
  // OC
  au: 'oc', nz: 'oc', pg: 'oc', fj: 'oc', sb: 'oc',
};

const getRegionOfCountry = (countryId: string): string => {
  const cleanId = countryId.toLowerCase().replace(/^_+/, '');
  return COUNTRY_TO_REGION[cleanId] || '';
};

const handleRegionClick = (hub: RegionHub) => {
  if (selectedRegion.value === hub.id) {
    selectedRegion.value = null;
    emit('filterCountry', '');
  } else {
    selectedRegion.value = hub.id;
    emit('filterCountry', hub.countryCode);
  }
};

const handleCountryClick = (countryId: string) => {
  const region = getRegionOfCountry(countryId);
  if (region) {
    const hub = REGION_HUBS.find(h => h.id === region);
    if (hub) handleRegionClick(hub);
  }
};

const hubMetrics = computed(() => {
  const metrics: Record<string, { total: number; critical: number; high: number; medium: number; low: number }> = {};
  for (const hub of REGION_HUBS) {
    metrics[hub.id] = { total: 0, critical: 0, high: 0, medium: 0, low: 0 };
  }
  for (const ioc of props.iocs) {
    if (ioc.ioc_type !== 'ip' && ioc.ioc_type !== 'domain' && ioc.ioc_type !== 'url') continue;
    let hash = 0;
    for (let i = 0; i < ioc.value.length; i++) {
      hash = ioc.value.charCodeAt(i) + ((hash << 5) - hash);
    }
    const index = Math.abs(hash) % REGION_HUBS.length;
    const assignedHub = REGION_HUBS[index];

    metrics[assignedHub.id].total++;
    if (ioc.severity === 'critical') metrics[assignedHub.id].critical++;
    else if (ioc.severity === 'high') metrics[assignedHub.id].high++;
    else if (ioc.severity === 'medium') metrics[assignedHub.id].medium++;
    else metrics[assignedHub.id].low++;
  }
  return metrics;
});

const getRegionClass = (countryId: string): string => {
  const region = getRegionOfCountry(countryId);
  if (!region) return 'fill-[#1e1e2f]';
  const stats = hubMetrics.value[region];
  if (stats && stats.total > 0) {
    if (stats.critical > 0) return 'fill-[#f7768e]/10 hover:fill-[#f7768e]/20';
    if (stats.high > 0) return 'fill-[#e0af68]/10 hover:fill-[#e0af68]/20';
    return 'fill-[#38bdf8]/15 hover:fill-[#38bdf8]/25';
  }
  return 'fill-bg-tertiary/5';
};

const activeHubInfo = computed(() => {
  if (!selectedRegion.value) return null;
  return REGION_HUBS.find(h => h.id === selectedRegion.value) || null;
});

const activeHubStats = computed(() => {
  if (!selectedRegion.value) return null;
  return hubMetrics.value[selectedRegion.value] || null;
});
</script>

<template>
  <div class="bg-bg-secondary border border-border-primary/80 rounded-2xl p-4 backdrop-blur-md relative overflow-hidden flex flex-col h-full select-none">
    <!-- Map Header -->
    <div class="flex items-center justify-between mb-2 shrink-0">
      <div class="flex items-center gap-2">
        <Globe class="w-4 h-4 text-accent-blue" />
        <h3 class="text-xs font-semibold text-text-primary uppercase tracking-wider">Geographic Threat Distribution Map</h3>
      </div>
      <div class="flex items-center gap-3 text-[9px] text-text-tertiary font-mono">
        <span class="flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-[#f7768e] block"></span> Critical</span>
        <span class="flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-[#e0af68] block"></span> High</span>
        <span class="flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-[#38bdf8] block"></span> Standard</span>
      </div>
    </div>

    <!-- Map Canvas Body -->
    <div class="flex-1 min-h-[220px] relative border border-border-primary/20 rounded-xl bg-[#030307]/50 flex items-center justify-center overflow-hidden">
      <!-- High-tech abstract grid world map SVG -->
      <svg class="w-full h-full select-none" viewBox="30.767 241.591 784.077 458.627" fill="none" xmlns="http://www.w3.org/2000/svg">
        <g id="world-paths">
${parsedPaths}
        </g>

        <!-- Connecting data beams (wireframe grids) -->
        <g id="data-beams" opacity="0.3">
          <path d="M220,390 L440,350" stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.75" stroke-dasharray="2 2" />
          <path d="M440,350 L640,410" stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.75" stroke-dasharray="2 2" />
          <path d="M320,580 L490,510" stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.75" stroke-dasharray="2 2" />
          <path d="M490,510 L640,410" stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.75" stroke-dasharray="2 2" />
          <path d="M220,390 L320,580" stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.75" stroke-dasharray="2 2" />
          <path d="M640,410 L710,640" stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.75" stroke-dasharray="2 2" />
        </g>

        <!-- Interactive threat hub coordinate nodes -->
        <g v-for="hub in REGION_HUBS" :key="hub.id" class="cursor-pointer group" @click="handleRegionClick(hub)">
          <!-- Glowing outer pulse ring -->
          <circle
            :cx="hub.x"
            :cy="hub.y"
            :r="selectedRegion === hub.id ? 22 : 12"
            :class="[
              selectedRegion === hub.id ? 'stroke-accent-blue animate-pulse' : 'stroke-border-primary/40 group-hover:stroke-white/80',
              hubMetrics[hub.id].critical > 0 ? 'text-[#f7768e]' : hubMetrics[hub.id].high > 0 ? 'text-[#e0af68]' : 'text-accent-blue'
            ]"
            stroke-width="1.5"
            fill="none"
          />
          <circle
            v-if="selectedRegion === hub.id"
            :cx="hub.x"
            :cy="hub.y"
            r="30"
            class="stroke-accent-blue/30 opacity-50"
            stroke-width="0.5"
            stroke-dasharray="2 2"
            fill="none"
          />
          <!-- Core marker -->
          <circle
            :cx="hub.x"
            :cy="hub.y"
            :r="selectedRegion === hub.id ? 6 : 4.5"
            :fill="hubMetrics[hub.id].critical > 0 ? '#f7768e' : hubMetrics[hub.id].high > 0 ? '#e0af68' : '#38bdf8'"
            class="transition-all duration-300"
          />
          <!-- Text label -->
          <text
            :x="hub.x"
            :y="hub.y - 15"
            text-anchor="middle"
            class="font-mono text-[9px] font-bold fill-text-secondary group-hover:fill-white select-none transition-colors"
          >
            {{ hub.name }} ({{ hubMetrics[hub.id].total }})
          </text>
        </g>
      </svg>

      <!-- Selected region statistics HUD Overlay -->
      <div
        v-if="activeHubInfo && activeHubStats"
        class="absolute bottom-2.5 left-2.5 right-2.5 p-2 bg-[#09090e]/95 border border-border-primary/60 rounded-xl backdrop-blur-md flex items-center justify-between text-xs animate-fadeIn font-mono"
      >
        <div class="flex items-center gap-2">
          <MapPin class="w-3.5 h-3.5 text-accent-blue" />
          <div>
            <span class="font-bold text-white text-[11px] block leading-tight">{{ activeHubInfo.name }} Hub</span>
            <span class="text-[9px] text-text-tertiary block">Assigned Code: {{ activeHubInfo.countryCode }}</span>
          </div>
        </div>
        
        <div class="flex items-center gap-3 text-right">
          <div class="text-[9px] space-y-0.5 text-text-secondary leading-none">
            <div>Critical: <span class="text-[#f7768e] font-bold">{{ activeHubStats.critical }}</span></div>
            <div>High: <span class="text-[#e0af68] font-bold">{{ activeHubStats.high }}</span></div>
          </div>
          <div class="w-px h-6 bg-border-primary/20" />
          <button
            class="flex items-center gap-0.5 text-[9px] text-accent-blue font-bold hover:underline"
            @click="selectedRegion = null; emit('filterCountry', '')"
          >
            <ListFilter class="w-3 h-3" />
            <span>Clear Pivot</span>
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
#world-paths path {
  transition: fill 0.3s ease, stroke 0.3s ease;
}
#world-paths path:hover {
  fill: rgba(56, 189, 248, 0.25) !important;
  stroke: rgba(56, 189, 248, 0.6) !important;
}

@keyframes fadeIn {
  from { opacity: 0; transform: translateY(3px); }
  to { opacity: 1; transform: translateY(0); }
}
.animate-fadeIn {
  animation: fadeIn 0.2s ease-out forwards;
}
</style>
`;

fs.writeFileSync(outputVuePath, vueTemplate);
console.log('Successfully wrote updated ThreatMap.vue!');
