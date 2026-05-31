<script setup lang="ts">
import { ref, computed } from 'vue';
import { Terminal, Copy, Check, ShieldAlert, X, ChevronRight } from 'lucide-vue-next';
import type { IOC } from '../types';

const props = defineProps<{
  ioc: IOC | null;
  isOpen: boolean;
}>();

const emit = defineEmits<{
  (e: 'close'): void;
}>();

type Dialect = 'splunk' | 'kql' | 'sigma';
const activeDialect = ref<Dialect>('splunk');
const copied = ref(false);

const targetIndex = ref('*');
const targetSourcetype = ref('*');
const deviceAction = ref('blocked');

const handleCopy = (text: string) => {
  navigator.clipboard.writeText(text);
  copied.value = true;
  setTimeout(() => { copied.value = false; }, 2000);
};

// Generate Splunk SPL query matching the indicator
const splunkQuery = computed(() => {
  if (!props.ioc) return '';
  const value = props.ioc.value;
  const idx = targetIndex.value.trim() || '*';
  const st = targetSourcetype.value.trim() || '*';
  switch (props.ioc.ioc_type) {
    case 'ip':
      return `index="${idx}" sourcetype="${st}" (src_ip="${value}" OR dst_ip="${value}" OR ip="${value}")\n| stats count BY src_ip, dst_ip, sourcetype`;
    case 'domain':
      return `index="${idx}" sourcetype="${st}" (query="${value}" OR site="${value}" OR domain="${value}")\n| stats count BY site, sourcetype`;
    case 'url':
      return `index="${idx}" sourcetype="${st}" (url="${value}" OR request="${value}")\n| stats count BY url, src_ip`;
    case 'hash':
      return `index="${idx}" sourcetype="${st}" (file_hash="${value}" OR md5="${value}" OR sha256="${value}")\n| stats count BY file_name, file_hash, dest`;
    case 'cve':
      return `index="${idx}" sourcetype=signature_ids signature_id="*${value}*"\n| stats count BY signature_id, dest, severity`;
    default:
      return `index="${idx}" sourcetype="${st}" "${value}"`;
  }
});

// Generate Microsoft Sentinel KQL query matching the indicator
const kqlQuery = computed(() => {
  if (!props.ioc) return '';
  const value = props.ioc.value;
  const tblPrefix = targetIndex.value.trim() !== '*' ? targetIndex.value.trim() : '';
  const prefix = tblPrefix ? `${tblPrefix}\n| ` : '';
  switch (props.ioc.ioc_type) {
    case 'ip':
      return `${prefix}CommonSecurityLog\n| where SourceIP == "${value}" or DestinationIP == "${value}"\n| where DeviceAction == "${deviceAction.value}"\n| summarize ConnectionCount = count() by SourceIP, DestinationIP, DeviceAction`;
    case 'domain':
      return `${prefix}DnsEvents\n| where Name has "${value}"\n| summarize RequestCount = count() by Name, ClientIP`;
    case 'url':
      return `${prefix}WebSessionEvents\n| where Url has "${value}"\n| summarize Count = count() by Url, SourceIP, Username`;
    case 'hash':
      return `${prefix}DeviceFileEvents\n| where MD5 == "${value}" or SHA256 == "${value}"\n| summarize FileCount = count() by FileName, FolderPath, DeviceName`;
    case 'cve':
      return `${prefix}SecurityAlert\n| where AlertName has "${value}" or Description has "${value}"\n| summarize AlertCount = count() by AlertName, Severity, AlertSeverity`;
    default:
      return `${prefix}search "${value}"\n| summarize count() by $table`;
  }
});

// Generate Sigma Rule yaml matching the indicator
const sigmaRule = computed(() => {
  if (!props.ioc) return '';
  const value = props.ioc.value;
  const iocId = props.ioc.id;
  const cleanTitle = props.ioc.title ? props.ioc.title.replace(/"/g, '') : `${props.ioc.ioc_type.toUpperCase()} Indicator Detection`;
  
  return `title: Detect ${cleanTitle}
id: 2026-aegis-rule-${iocId}
status: experimental
description: Detection logic matching identified Aegis indicator of compromise
references:
    - https://api.aegisintel.internal/iocs/${iocId}
author: Aegis AI Analyst
date: 2026/05/31
logsource:
    category: ${props.ioc.ioc_type === 'ip' ? 'network_connection' : props.ioc.ioc_type === 'hash' ? 'file_event' : 'dns'}
detection:
    selection:
        ${props.ioc.ioc_type === 'ip' ? `DestinationIp: '${value}'` : props.ioc.ioc_type === 'domain' ? `DnsQuery: '${value}'` : props.ioc.ioc_type === 'hash' ? `Hashes|contains: '${value}'` : `IndicatorValue: '${value}'`}
    condition: selection
falsepositives:
    - Administrative vulnerability scanning
    - Legitimate developer testing
level: ${props.ioc.severity === 'critical' ? 'critical' : props.ioc.severity === 'high' ? 'high' : 'medium'}`;
});

const activeCode = computed(() => {
  if (activeDialect.value === 'splunk') return splunkQuery.value;
  if (activeDialect.value === 'kql') return kqlQuery.value;
  return sigmaRule.value;
});
</script>

<template>
  <div
    class="fixed inset-y-0 right-0 z-50 w-[420px] bg-bg-secondary border-l border-border-primary/95 shadow-2xl flex flex-col transition-transform duration-300 ease-in-out transform"
    :class="isOpen ? 'translate-x-0' : 'translate-x-full'"
  >
    <!-- Drawer Header -->
    <div class="px-5 py-4 border-b border-border-primary flex items-center justify-between bg-bg-primary/20">
      <div class="flex items-center gap-2">
        <Terminal class="w-4 h-4 text-accent-blue" />
        <h3 class="text-xs font-bold text-text-primary uppercase tracking-wider">SIEM Hunt Query Sandbox</h3>
      </div>
      <button @click="emit('close')" class="p-1 rounded-md text-text-tertiary hover:text-white hover:bg-bg-tertiary/40">
        <X class="w-4 h-4" />
      </button>
    </div>

    <div v-if="ioc" class="flex-1 flex flex-col min-h-0 overflow-y-auto p-5 space-y-5">
      
      <!-- Selected Indicator Context -->
      <div class="p-4 rounded-xl bg-bg-primary/40 border border-border-primary/30 flex items-start gap-3">
        <div class="w-7 h-7 rounded-lg bg-accent-blue/10 flex items-center justify-center shrink-0 mt-0.5">
          <ShieldAlert class="w-4 h-4 text-accent-blue" />
        </div>
        <div class="min-w-0">
          <span class="text-[10px] text-text-tertiary uppercase font-mono block">Context Indicator</span>
          <span class="text-xs font-mono font-bold text-white break-all select-all mt-0.5 block">{{ ioc.value }}</span>
          <span class="inline-block mt-2 text-[9px] px-1.5 py-0.5 rounded-full bg-severity-critical-bg text-severity-critical font-bold border border-severity-critical/20 uppercase tracking-wide">
            {{ ioc.severity }} Severity
          </span>
        </div>
      </div>

      <!-- Dialect Tabs -->
      <div class="flex border-b border-border-primary/40 p-0.5 bg-bg-primary/30 rounded-lg">
        <button
          v-for="dialect in [
            { id: 'splunk' as const, label: 'Splunk SPL' },
            { id: 'kql' as const, label: 'Azure KQL' },
            { id: 'sigma' as const, label: 'Sigma Rule' }
          ]"
          :key="dialect.id"
          class="flex-1 py-1.5 text-[11px] font-semibold rounded-md transition-all"
          :class="activeDialect === dialect.id
            ? 'bg-accent-blue/15 text-accent-blue border border-accent-blue/20'
            : 'text-text-secondary hover:text-white hover:bg-bg-tertiary/20'"
          @click="activeDialect = dialect.id"
        >
          {{ dialect.label }}
        </button>
      </div>

      <!-- Customizer Controls (Usability Upgrade) -->
      <div v-if="activeDialect !== 'sigma'" class="p-3.5 rounded-xl bg-bg-primary/20 border border-border-primary/20 space-y-3 text-xs shrink-0">
        <div class="flex items-center justify-between border-b border-border-primary/20 pb-1.5 mb-1">
          <span class="text-[10px] text-text-tertiary uppercase font-mono tracking-wider font-bold">Query Parameters</span>
          <span class="text-[9px] text-accent-blue font-mono">Live Sync</span>
        </div>
        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-[10px] text-text-secondary mb-1 font-mono">Target Index / DB</label>
            <input
              type="text"
              v-model="targetIndex"
              class="px-2.5 py-1 rounded border border-border-primary/50 bg-bg-primary text-white font-mono text-[11px] w-full focus:outline-none focus:border-accent-blue"
              placeholder="*"
            />
          </div>
          <div>
            <label class="block text-[10px] text-text-secondary mb-1 font-mono">Target Sourcetype</label>
            <input
              type="text"
              v-model="targetSourcetype"
              class="px-2.5 py-1 rounded border border-border-primary/50 bg-bg-primary text-white font-mono text-[11px] w-full focus:outline-none focus:border-accent-blue"
              placeholder="*"
            />
          </div>
        </div>
        <div class="mt-2">
          <label class="block text-[10px] text-text-secondary mb-1 font-mono">Device Action Filter</label>
          <input
            type="text"
            v-model="deviceAction"
            class="px-2.5 py-1 rounded border border-border-primary/50 bg-bg-primary text-white font-mono text-[11px] w-full focus:outline-none focus:border-accent-blue"
            placeholder="blocked"
          />
        </div>
      </div>

      <!-- Simulated Code Editor Layout -->
      <div class="flex-1 min-h-[220px] bg-bg-primary border border-border-primary/50 rounded-xl overflow-hidden flex flex-col font-mono relative group">
        <!-- Editor Header Tabs -->
        <div class="px-4 py-2 border-b border-border-primary/40 bg-bg-secondary/40 flex items-center justify-between text-[10px] select-none text-text-tertiary">
          <span class="flex items-center gap-1.5"><span class="w-2.5 h-2.5 rounded-full bg-red-500/80 block"></span> {{ activeDialect === 'sigma' ? 'rule.yml' : 'query.txt' }}</span>
          <button
            class="flex items-center gap-1 p-1 hover:text-white transition-colors"
            title="Copy query code"
            @click="handleCopy(activeCode)"
          >
            <Check v-if="copied" class="w-3.5 h-3.5 text-accent-green" />
            <Copy v-else class="w-3.5 h-3.5" />
            <span>Copy</span>
          </button>
        </div>

        <!-- Line Numbers + Code area -->
        <div class="flex-1 flex text-[11px] overflow-auto p-4 leading-relaxed">
          <!-- Line Numbers -->
          <div class="text-text-tertiary/30 text-right pr-3 select-none border-r border-border-primary/10 shrink-0">
            <div v-for="n in activeCode.split('\n').length" :key="n">{{ n }}</div>
          </div>
          <!-- Code blocks -->
          <pre class="pl-4 text-text-secondary whitespace-pre overflow-x-auto text-[11px] select-text w-full leading-relaxed"><code class="text-accent-cyan">{{ activeCode }}</code></pre>
        </div>
      </div>

      <!-- Diagnostic Tips -->
      <div class="p-4 rounded-xl bg-bg-primary/20 border border-border-primary/20 space-y-2">
        <h4 class="text-xs font-semibold text-text-primary flex items-center gap-1.5">
          <ChevronRight class="w-3.5 h-3.5 text-accent-blue" />
          <span>Operational Guidance</span>
        </h4>
        <p class="text-[11px] text-text-secondary leading-relaxed">
          {{ activeDialect === 'splunk'
            ? 'Run this query in Splunk Search & Reporting. Ensure indices and sourcetypes match your host configurations.'
            : activeDialect === 'kql'
            ? 'Execute this query in Microsoft Sentinel Log Analytics. Adjust tables (e.g. DeviceEvents or DnsEvents) to align with connectors.'
            : 'Sigma rules serve as tool-agnostic signatures. Convert this YAML to your target SIEM dialect using sigmac translator tools.'
          }}
        </p>
      </div>

    </div>
  </div>
</template>

<style scoped>
pre {
  background-color: transparent !important;
  border: none !important;
  border-radius: 0 !important;
  padding: 0 !important;
  margin: 0 !important;
}
</style>
