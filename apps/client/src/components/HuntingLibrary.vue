<script setup lang="ts">
import { ref, computed } from 'vue';
import { Search, Copy, Check, Terminal, ShieldAlert, Cpu, Filter } from 'lucide-vue-next';

interface HuntRule {
  id: string;
  title: string;
  cve: string;
  severity: 'critical' | 'high' | 'medium';
  platform: 'Windows' | 'Linux' | 'Cloud' | 'Multi';
  description: string;
  mitreMapping: string;
  splunk: string;
  kql: string;
  sigma: string;
}

const rules = ref<HuntRule[]>([
  {
    id: 'log4shell',
    title: 'Log4Shell JNDI Lookup Attempt',
    cve: 'CVE-2021-44228',
    severity: 'critical',
    platform: 'Multi',
    description: 'Detects suspicious JNDI lookup patterns containing protocols commonly used for exploiting Log4Shell (ldap, rmi, dns, ldaps, nis, iiop, corba, nds) in web application gateway logs.',
    mitreMapping: 'T1190 - Exploit Public-Facing Application',
    splunk: `index=* OR sourcetype=* "jndi" ("ldap" OR "rmi" OR "dns" OR "ldaps" OR "nis" OR "iiop" OR "corba" OR "nds")\n| eval defanged_uri = replace(raw_uri, "\\.", "[.]")\n| table _time, host, src_ip, defanged_uri, user_agent`,
    kql: `DeviceLogEvents\n| where AdditionalFields has "jndi:"\n| extend Protocol = extract(@"jndi:([a-zA-Z]+)://", 1, AdditionalFields)\n| where Protocol in ("ldap", "rmi", "dns", "ldaps", "nis", "iiop", "corba", "nds")\n| project TimeGenerated, DeviceName, SourceIP, Protocol, AdditionalFields`,
    sigma: `title: Log4Shell JNDI Lookup Attempt\nid: 757efad6-8ff4-46c5-84f9-b8833d7bfa56\nstatus: stable\ndescription: Detects JNDI lookup attempts containing protocols commonly used for exploiting Log4Shell (CVE-2021-44228) inside web requests.\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    c-uri|contains:\n      - 'jndi:ldap:'\n      - 'jndi:rmi:'\n      - 'jndi:dns:'\n      - 'jndi:ldaps:'\n      - 'jndi:nis:'\n      - 'jndi:iiop:'\n      - 'jndi:corba:'\n      - 'jndi:nds:'\n  condition: selection\nfalsepositives:\n  - Penetration testing activity\nlevel: critical`
  },
  {
    id: 'spring4shell',
    title: 'Spring4Shell ClassLoader Manipulation',
    cve: 'CVE-2022-22965',
    severity: 'critical',
    platform: 'Multi',
    description: 'Detects classLoader manipulation HTTP requests targeting Spring Framework applications to upload web shells or execute arbitrary code.',
    mitreMapping: 'T1190 - Exploit Public-Facing Application, T1505.003 - Web Shell',
    splunk: `index=* sourcetype=access_combined ("class.module.classLoader.resources.context.parent.pipeline.first.pattern" OR "classloader")\n| table _time, host, clientip, uri, status, bytes`,
    kql: `W3CIASLog\n| where csUriQuery has "classLoader" or csUriQuery has "class.module.classLoader"\n| project TimeGenerated, Computer, cIP, csMethod, csUriStem, csUriQuery, scStatus`,
    sigma: `title: Spring4Shell ClassLoader Manipulation Attempt\nid: 61e1b439-0d2d-45db-9c3f-c1f0a133ff0f\nstatus: stable\ndescription: Detects classLoader manipulation payloads within query strings or HTTP POST bodies targeting Spring4Shell (CVE-2022-22965).\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    c-uri-query|contains:\n      - 'class.module.classLoader'\n      - 'classloader.resources'\n  condition: selection\nlevel: critical`
  },
  {
    id: 'proxylogon',
    title: 'ProxyLogon Exchange Server Exploit',
    cve: 'CVE-2021-26855',
    severity: 'critical',
    platform: 'Windows',
    description: 'Detects suspicious HTTP POST requests targeting Exchange Mailbox servers using static OWA authentication theme resource resource paths to bypass authorization.',
    mitreMapping: 'T1190 - Exploit Public-Facing Application',
    splunk: `index=* sourcetype=MSExchange:OWA:IIS "/owa/auth/Current/themes/resources/" method=POST\n| stats count by _time, host, src_ip, uri, user_agent`,
    kql: `W3CIASLog\n| where csMethod == "POST" and csUriStem has "/owa/auth/Current/themes/resources/"\n| project TimeGenerated, Computer, cIP, csUriStem, csUserAgent, scStatus`,
    sigma: `title: ProxyLogon Exchange Exploitation\nid: 1cd94b7b-2cf7-4f62-b9cf-2b81467cc7bb\nstatus: stable\ndescription: Detects suspicious path traversals targeting Exchange mail services via ProxyLogon CVE-2021-26855.\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  category: webserver\ndetection:\n  selection:\n    cs-method: 'POST'\n    cs-uri-stem|contains:\n      - '/owa/auth/Current/themes/resources/'\n  condition: selection\nlevel: critical`
  },
  {
    id: 'printnightmare',
    title: 'PrintNightmare Driver Execution',
    cve: 'CVE-2021-34527',
    severity: 'high',
    platform: 'Windows',
    description: 'Detects suspicious print spooler service activity loading unverified drivers, or launching cmd/powershell execution shells directly under the spooler process context.',
    mitreMapping: 'T1068 - Exploitation for Privilege Escalation',
    splunk: `index=* sourcetype=WinEventLog:Security EventCode=808 OR EventCode=316\n| stats count by _time, ComputerName, SecurityID, Message`,
    kql: `DeviceProcessEvents\n| where InitiatingProcessFileName =~ "spoolsv.exe"\n| where FileName in~ ("rundll32.exe", "cmd.exe", "powershell.exe", "net.exe")\n| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine`,
    sigma: `title: PrintNightmare Driver Load Detection\nid: ac2849b2-38d7-4cd1-9c66-e82b3d81b94b\nstatus: stable\ndescription: Detects suspicious spooler service loading custom DLLs or launching shells under print spooler context (CVE-2021-34527).\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  product: windows\n  service: print-spooler\ndetection:\n  selection:\n    EventID:\n      - 808\n      - 316\n  condition: selection\nlevel: high`
  },
  {
    id: 'follina',
    title: 'Follina MSDT Execution',
    cve: 'CVE-2022-30190',
    severity: 'high',
    platform: 'Windows',
    description: 'Detects Microsoft Office processes spawning msdt.exe (Microsoft Support Diagnostic Tool) to download and run malicious remote HTML scripts.',
    mitreMapping: 'T1566.001 - Spearphishing Attachment, T1218 - System Binary Proxy Execution',
    splunk: `index=* sourcetype=WinEventLog:Security (ParentImage="*winword.exe" OR ParentImage="*excel.exe" OR ParentImage="*powerpnt.exe") Image="*msdt.exe"\n| table _time, host, user, Image, CommandLine`,
    kql: `DeviceProcessEvents\n| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")\n| where FileName =~ "msdt.exe" and ProcessCommandLine has "it_RebrowseForFile"\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, ProcessCommandLine`,
    sigma: `title: Follina Office Spawning MSDT\nid: e8f6ad40-1a74-4b5b-ad7d-7ef8ad4b29bb\nstatus: stable\ndescription: Detects Microsoft Office products (Word, Excel, PowerPoint) launching MSDT.exe which might indicate Follina exploitation (CVE-2022-30190).\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  product: windows\n  category: process_creation\ndetection:\n  selection:\n    ParentImage|endswith:\n      - '\\winword.exe'\n      - '\\excel.exe'\n      - '\\powerpnt.exe'\n      - '\\outlook.exe'\n    Image|endswith: '\\msdt.exe'\n  condition: selection\nlevel: high`
  },
  {
    id: 'dirtypipe',
    title: 'DirtyPipe Exploit Process Detection',
    cve: 'CVE-2022-0847',
    severity: 'high',
    platform: 'Linux',
    description: 'Detects suspicious writes to read-only page caches in Linux environments, specifically monitoring unusual access to system config files (like /etc/passwd or /etc/shadow) by unprivileged processes.',
    mitreMapping: 'T1068 - Exploitation for Privilege Escalation',
    splunk: `index=* sourcetype=linux_audit type=ANOM_ABEND OR type=SYSCALL (syscall=write OR syscall=pwrite) success=yes exe!=*systemd* (file="/etc/passwd" OR file="/etc/shadow")\n| table _time, host, key, exe, file`,
    kql: `DeviceProcessEvents\n| where OSPlatform == "Linux"\n| where FileName in ("passwd", "shadow") and InitiatingProcessFileName != "userhelper"\n| where InitiatingProcessCommandLine has "write" or ProcessCommandLine has "pwrite"\n| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, FileName, FolderPath`,
    sigma: `title: Linux Privilege Escalation via DirtyPipe\nid: fa7082cd-3e91-447c-ae0d-cbefdf83a216\nstatus: stable\ndescription: Detects suspicious process writes to critical Linux read-only files (like /etc/passwd) typical of DirtyPipe (CVE-2022-0847) exploitation attempts.\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains:\n      - 'passwd'\n      - 'shadow'\n    CommandLine|contains:\n      - '/tmp/'\n      - 'dirty'\n  condition: selection\nlevel: high`
  },
  {
    id: 'zerologon',
    title: 'Zerologon AD Credential Reset',
    cve: 'CVE-2020-1472',
    severity: 'critical',
    platform: 'Windows',
    description: 'Detects remote domain controller authentication bypass attempts where the computer password is set to an empty string via MS-NRPC protocols.',
    mitreMapping: 'T1210 - Exploitation of Remote Services, T1078.002 - Domain Accounts',
    splunk: `index=* sourcetype=WinEventLog:Security EventCode=4742 OR EventCode=5805 "password" "empty"\n| table _time, host, TargetUserName, SubjectUserName, Message`,
    kql: `SecurityEvent\n| where EventID in (4742, 5805)\n| where TargetUserName == "ANONYMOUS LOGON" or TargetUserName endswith "$"\n| where Message has "Password last set" and Message has "1/1/1601"\n| project TimeGenerated, Computer, TargetUserName, SubjectUserName, Message`,
    sigma: `title: Zerologon Authentication Attempt\nid: 9df03da2-8176-47b2-8418-508b1a89c47e\nstatus: stable\ndescription: Detects Active Directory Domain Controller Event IDs indicating remote machine account password reset attempts via Netlogon Zerologon CVE-2020-1472.\nauthor: Aegis ATI SecOps team\ndate: 2026/05/31\nlogsource:\n  product: windows\n  service: security\ndetection:\n  selection:\n    EventID: 4742\n    TargetUserName|endswith: '$'\n    PasswordLastSet: '1601-01-01 00:00:00'\n  condition: selection\nlevel: critical`
  }
]);

const searchQuery = ref('');
const selectedSeverity = ref<string>('all');
const selectedPlatform = ref<string>('all');
const activeDialect = ref<'splunk' | 'kql' | 'sigma'>('splunk');
const activeRuleId = ref<string>(rules.value[0].id);
const copySuccess = ref(false);

const activeRule = computed(() => {
  return rules.value.find(r => r.id === activeRuleId.value) || rules.value[0];
});

const filteredRules = computed(() => {
  return rules.value.filter(rule => {
    const matchesSearch = rule.title.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                          rule.cve.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
                          rule.description.toLowerCase().includes(searchQuery.value.toLowerCase());
    
    const matchesSeverity = selectedSeverity.value === 'all' || rule.severity === selectedSeverity.value;
    const matchesPlatform = selectedPlatform.value === 'all' || rule.platform.toLowerCase() === selectedPlatform.value.toLowerCase();
    
    return matchesSearch && matchesSeverity && matchesPlatform;
  });
});

const getSeverityClass = (severity: string) => {
  if (severity === 'critical') return 'bg-red-500/10 text-red-400 border-red-500/20';
  if (severity === 'high') return 'bg-amber-500/10 text-amber-400 border-amber-500/20';
  return 'bg-blue-500/10 text-blue-400 border-blue-500/20';
};

const selectRule = (id: string) => {
  activeRuleId.value = id;
  copySuccess.value = false;
};

const activeCode = computed(() => {
  if (activeDialect.value === 'splunk') return activeRule.value.splunk;
  if (activeDialect.value === 'kql') return activeRule.value.kql;
  return activeRule.value.sigma;
});

const copyRuleText = async () => {
  try {
    await navigator.clipboard.writeText(activeCode.value);
    copySuccess.value = true;
    setTimeout(() => {
      copySuccess.value = false;
    }, 2000);
  } catch (err) {
    console.error('Failed to copy rule:', err);
  }
};
</script>

<template>
  <div class="h-full flex flex-col overflow-hidden">
    <!-- Subheader Search / Filters -->
    <div class="p-5 border-b border-border-primary/40 bg-bg-secondary/40 shrink-0 flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
      <div class="relative w-full md:w-80">
        <Search class="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search by CVE, exploit, rule..."
          class="w-full pl-10 pr-4 py-2 text-xs rounded-xl bg-bg-primary border border-border-primary text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-secondary focus:ring-1 focus:ring-border-secondary transition-all"
        />
      </div>

      <div class="flex items-center gap-3 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
        <!-- Severity Filter -->
        <div class="flex items-center gap-1.5 bg-bg-primary border border-border-primary rounded-xl px-2.5 py-1.5 shrink-0">
          <ShieldAlert class="w-3.5 h-3.5 text-text-tertiary" />
          <select v-model="selectedSeverity" class="bg-transparent text-xs text-text-secondary focus:outline-none border-none pr-4 cursor-pointer font-semibold">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
          </select>
        </div>

        <!-- Platform Filter -->
        <div class="flex items-center gap-1.5 bg-bg-primary border border-border-primary rounded-xl px-2.5 py-1.5 shrink-0">
          <Filter class="w-3.5 h-3.5 text-text-tertiary" />
          <select v-model="selectedPlatform" class="bg-transparent text-xs text-text-secondary focus:outline-none border-none pr-4 cursor-pointer font-semibold">
            <option value="all">All Platforms</option>
            <option value="Windows">Windows</option>
            <option value="Linux">Linux</option>
            <option value="Multi">Multi-Platform</option>
          </select>
        </div>
      </div>
    </div>

    <!-- Main Workspace Split Panel -->
    <div class="flex-1 flex overflow-hidden min-h-0">
      <!-- Left: List of Vulnerabilities -->
      <div class="w-full md:w-[350px] border-r border-border-primary/40 overflow-y-auto flex flex-col shrink-0">
        <div v-if="filteredRules.length === 0" class="flex-1 flex flex-col items-center justify-center p-8 text-center text-text-tertiary">
          <ShieldAlert class="w-8 h-8 opacity-40 mb-3" />
          <p class="text-xs">No hunting rules match your current search parameters.</p>
        </div>
        <div v-else class="divide-y divide-border-primary/30">
          <button
            v-for="rule in filteredRules"
            :key="rule.id"
            class="w-full text-left p-4 hover:bg-bg-secondary/40 transition-all flex flex-col gap-2 relative border-l-2"
            :class="[
              activeRuleId === rule.id 
                ? 'bg-bg-secondary/70 border-accent-blue' 
                : 'border-transparent'
            ]"
            @click="selectRule(rule.id)"
          >
            <div class="flex items-start justify-between">
              <span class="text-xs font-bold text-white leading-tight line-clamp-1 flex-1 pr-2">{{ rule.title }}</span>
              <span class="text-[9px] font-bold px-2 py-0.5 rounded-full border tracking-wide uppercase shrink-0" :class="getSeverityClass(rule.severity)">
                {{ rule.severity }}
              </span>
            </div>
            
            <p class="text-[10px] text-text-secondary line-clamp-2 pr-1">{{ rule.description }}</p>
            
            <div class="flex items-center justify-between text-[9px] text-text-tertiary font-mono pt-1">
              <span>{{ rule.cve }}</span>
              <span class="px-1.5 py-0.5 rounded bg-bg-primary/80 border border-border-primary/40 font-semibold">{{ rule.platform }}</span>
            </div>
          </button>
        </div>
      </div>

      <!-- Right: Rule Explorer / Editor -->
      <div v-if="activeRule" class="flex-1 flex flex-col overflow-hidden bg-bg-primary/10">
        <!-- Details Header -->
        <div class="p-5 border-b border-border-primary/40 shrink-0">
          <div class="flex flex-col md:flex-row md:items-start justify-between gap-4">
            <div>
              <div class="flex items-center gap-2 mb-1.5 flex-wrap">
                <h3 class="text-base font-extrabold text-white">{{ activeRule.title }}</h3>
                <span class="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-bg-secondary border border-border-primary text-accent-blue">{{ activeRule.cve }}</span>
              </div>
              <p class="text-xs text-text-secondary leading-relaxed max-w-2xl">{{ activeRule.description }}</p>
              
              <div class="flex items-center gap-4 text-[10px] text-text-tertiary mt-3 font-mono">
                <div>MITRE Map: <span class="text-text-secondary font-semibold">{{ activeRule.mitreMapping }}</span></div>
              </div>
            </div>
          </div>
        </div>

        <!-- Rules Tabbed Viewer -->
        <div class="flex-1 flex flex-col overflow-hidden">
          <!-- Selection bar -->
          <div class="px-5 py-2.5 border-b border-border-primary/30 bg-bg-secondary/40 shrink-0 flex items-center justify-between">
            <div class="flex items-center gap-1">
              <button
                v-for="dialect in [
                  { id: 'splunk' as const, label: 'Splunk SPL' },
                  { id: 'kql' as const, label: 'Azure KQL' },
                  { id: 'sigma' as const, label: 'Sigma Rule' }
                ]"
                :key="dialect.id"
                class="px-3 py-1.5 rounded-lg text-[10px] font-bold transition-all"
                :class="[
                  activeDialect === dialect.id
                    ? 'bg-bg-primary border border-border-primary text-white shadow-sm'
                    : 'text-text-tertiary hover:text-text-secondary border border-transparent'
                ]"
                @click="activeDialect = dialect.id"
              >
                {{ dialect.label }}
              </button>
            </div>

            <button
              class="flex items-center gap-1 px-3 py-1.5 text-[10px] font-bold rounded-lg border transition-all text-white bg-accent-blue border-accent-blue/30 hover:bg-accent-blue/80 shadow-md shadow-accent-blue/10"
              @click="copyRuleText"
            >
              <Check v-if="copySuccess" class="w-3.5 h-3.5 text-green-300" />
              <Copy v-else class="w-3.5 h-3.5" />
              <span>{{ copySuccess ? 'Copied!' : 'Copy Rule' }}</span>
            </button>
          </div>

          <!-- Code editor area -->
          <div class="flex-1 flex overflow-hidden font-mono text-xs">
            <!-- Line numbers -->
            <div class="w-10 border-r border-border-primary/20 py-4 select-none text-right pr-3 text-[10px] text-text-tertiary/40 bg-bg-secondary/20 shrink-0">
              <div v-for="n in activeCode.split('\n').length" :key="n">{{ n }}</div>
            </div>

            <!-- Code display -->
            <pre class="flex-1 p-4 overflow-auto text-text-secondary select-text whitespace-pre leading-relaxed select-all"><code>{{ activeCode }}</code></pre>
          </div>

          <!-- Quick Tip Footer -->
          <div class="p-3 border-t border-border-primary/40 bg-bg-secondary/20 shrink-0 flex items-center gap-2 text-[10px] text-text-tertiary">
            <Terminal class="w-3.5 h-3.5 text-accent-blue shrink-0" />
            <span>
              {{ activeDialect === 'splunk'
                ? 'Run this query in Splunk Search & Reporting. Adjust event types and source fields to align with internal configurations.'
                : activeDialect === 'kql'
                ? 'Execute this query in Microsoft Sentinel or Azure Monitor Log Analytics. Customize host filter conditions as needed.'
                : 'Deploy this Sigma signature with Sigmac or converter integrations to compile standard Splunk, Elastic, or Sentinel alerts.'
              }}
            </span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
