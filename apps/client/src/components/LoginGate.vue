<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { 
  Shield, Key, User, ShieldAlert, Check, Loader2, Server, 
  Mail, Building, AlertTriangle, ArrowLeft, Cpu, Database, Eye, EyeOff
} from 'lucide-vue-next';

const emit = defineEmits<{
  (e: 'login-success'): void;
}>();

const username = ref('');
const password = ref('');
const showPassword = ref(false);
const isLoading = ref(false);
const isTypingDemo = ref(false);
const loginError = ref('');
const apiHealth = ref<{ status: string; iocCount: number } | null>(null);

// Form Mode: 'login' | 'request' | 'request-success'
const formMode = ref<'login' | 'request' | 'request-success'>('login');
const requestName = ref('');
const requestEmail = ref('');
const requestJustification = ref('');
const requestLoading = ref(false);

const checkApiHealth = async () => {
  try {
    const res = await fetch('http://localhost:4001/health');
    if (res.ok) {
      apiHealth.value = await res.json();
    }
  } catch (err) {
    console.error('API health check failed:', err);
  }
};

onMounted(() => {
  checkApiHealth();
});

const handleLogin = async () => {
  if (!username.value || !password.value) {
    loginError.value = 'Operator ID and Security Key are required.';
    return;
  }

  isLoading.value = true;
  loginError.value = '';

  // Simulate authentication handshake/decryption verification phase
  setTimeout(() => {
    if (username.value === 'admin' && password.value === 'SecOps-ATI-2026') {
      sessionStorage.setItem('aegis-authenticated', 'true');
      emit('login-success');
    } else {
      loginError.value = 'ACCESS DENIED: Invalid Security Credentials.';
      password.value = '';
    }
    isLoading.value = false;
  }, 1000);
};

const correctionLogs = ref<string[]>([]);

// Typewriter Credentials Autofill Simulation with Autocorrect Demo
const triggerAutofillDemo = () => {
  if (isTypingDemo.value || isLoading.value) return;
  isTypingDemo.value = true;
  username.value = '';
  password.value = '';
  loginError.value = '';
  correctionLogs.value = [];

  const typoUser = 'admim@aegisintel.com';
  const correctUser = 'admin';
  const typoPass = 'SecOps-ATI-2025';
  const correctPass = 'SecOps-ATI-2026';

  let userIdx = 0;
  let passIdx = 0;

  const typeTypoUser = () => {
    if (userIdx < typoUser.length) {
      username.value += typoUser[userIdx];
      userIdx++;
      setTimeout(typeTypoUser, 40);
    } else {
      setTimeout(correctUserField, 350);
    }
  };

  const correctUserField = () => {
    correctionLogs.value.push('Evaluating input syntax for Operator ID...');
    setTimeout(() => {
      correctionLogs.value.push('WARN: Domain wrapper detected [aegisintel.com]');
      setTimeout(() => {
        correctionLogs.value.push('WARN: spelling alias correction needed [admim]');
        setTimeout(() => {
          correctionLogs.value.push('Action: Normalizing user principal and correcting alias...');
          setTimeout(() => {
            username.value = correctUser;
            correctionLogs.value.push('Success: Resolved Operator ID: admin');
            setTimeout(typeTypoPass, 400);
          }, 300);
        }, 400);
      }, 400);
    }, 400);
  };

  const typeTypoPass = () => {
    if (passIdx < typoPass.length) {
      password.value += typoPass[passIdx];
      passIdx++;
      setTimeout(typeTypoPass, 40);
    } else {
      setTimeout(correctPassField, 350);
    }
  };

  const correctPassField = () => {
    correctionLogs.value.push('Evaluating Cryptographic Key signature...');
    setTimeout(() => {
      correctionLogs.value.push('WARN: Outdated epoch signature [2025]');
      setTimeout(() => {
        correctionLogs.value.push('Action: Live-migrating session signature key...');
        setTimeout(() => {
          password.value = correctPass;
          correctionLogs.value.push('Success: Key upgraded to SecOps-ATI-2026');
          setTimeout(() => {
            isTypingDemo.value = false;
            correctionLogs.value.push('SYSTEM: Secure credentials verified. Ready for handshake.');
          }, 400);
        }, 300);
      }, 400);
    }, 400);
  };

  typeTypoUser();
};

const handleRequestAccess = () => {
  if (!requestName.value || !requestEmail.value || !requestJustification.value) return;
  requestLoading.value = true;
  setTimeout(() => {
    requestLoading.value = false;
    formMode.value = 'request-success';
  }, 1200);
};

const resetRequestForm = () => {
  requestName.value = '';
  requestEmail.value = '';
  requestJustification.value = '';
  formMode.value = 'login';
};
</script>

<template>
  <div class="min-h-screen w-full flex bg-[#070a13] font-sans overflow-hidden select-none relative">
    <!-- Cyber Grid Canvas -->
    <div class="absolute inset-0 bg-[linear-gradient(to_right,#1f293706_1px,transparent_1px),linear-gradient(to_bottom,#1f293706_1px,transparent_1px)] bg-[size:32px_32px] pointer-events-none"></div>

    <!-- LEFT: Showcase Panel (Hidden on Mobile) -->
    <div class="hidden lg:flex lg:w-1/2 p-12 flex-col justify-between relative overflow-hidden border-r border-border-primary/30 bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-accent-blue/10 via-[#070a13] to-[#070a13]">
      <!-- Background glowing orb -->
      <div class="absolute top-20 right-[-100px] w-96 h-96 rounded-full bg-accent-blue/5 blur-[120px] pointer-events-none"></div>
      
      <!-- Brand header -->
      <div class="flex items-center gap-3 relative z-10">
        <div class="w-10 h-10 rounded-xl bg-accent-blue/10 border border-accent-blue/30 flex items-center justify-center shadow-lg">
          <Shield class="w-5 h-5 text-accent-blue" />
        </div>
        <div>
          <h1 class="text-sm font-black text-white tracking-widest leading-none">AEGIS THREAT INTEL</h1>
          <span class="text-[9px] text-text-tertiary font-mono tracking-widest uppercase block mt-1">Air-Gapped Command Center</span>
        </div>
      </div>

      <!-- Feature highlights -->
      <div class="space-y-8 max-w-lg relative z-10 my-auto">
        <div>
          <h2 class="text-3xl font-extrabold text-white leading-tight mb-2">On-Premises Threat Security Gate</h2>
          <p class="text-xs text-text-secondary leading-relaxed">ATI orchestrates local logs correlation, custom ingestion pipelines, and cognitive analysis entirely inside your secure private boundary.</p>
        </div>

        <div class="space-y-6">
          <div class="flex items-start gap-4">
            <div class="w-8 h-8 rounded-lg bg-bg-secondary border border-border-primary flex items-center justify-center shrink-0">
              <Cpu class="w-4 h-4 text-accent-blue" />
            </div>
            <div>
              <h4 class="text-xs font-bold text-white uppercase tracking-wider mb-1 font-mono">Air-Gapped Data Privacy</h4>
              <p class="text-[11px] text-text-tertiary leading-relaxed">No tracking hooks, query leaks, or search telemetry. Database search indexings utilize localized SQLite FTS5 queries offline.</p>
            </div>
          </div>

          <div class="flex items-start gap-4">
            <div class="w-8 h-8 rounded-lg bg-bg-secondary border border-border-primary flex items-center justify-center shrink-0">
              <Database class="w-4 h-4 text-accent-green" />
            </div>
            <div>
              <h4 class="text-xs font-bold text-white uppercase tracking-wider mb-1 font-mono">Automated Feeds Correlation</h4>
              <p class="text-[11px] text-text-tertiary leading-relaxed">Aggregates global indicators (CISA KEV, URLhaus, ThreatFox) hourly, compiling intelligence dynamically for instant matching.</p>
            </div>
          </div>

          <div class="flex items-start gap-4">
            <div class="w-8 h-8 rounded-lg bg-bg-secondary border border-border-primary flex items-center justify-center shrink-0">
              <ShieldAlert class="w-4 h-4 text-accent-cyan" />
            </div>
            <div>
              <h4 class="text-xs font-bold text-white uppercase tracking-wider mb-1 font-mono">Cognitive SOC Hunting</h4>
              <p class="text-[11px] text-text-tertiary leading-relaxed">Generates production Splunk, Sentinel KQL, and Sigma alerts matching indicators instantly to accelerate threat response.</p>
            </div>
          </div>
        </div>
      </div>

      <!-- Footer system health info -->
      <div class="flex items-center gap-6 border-t border-border-primary/40 pt-6 relative z-10">
        <div class="flex items-center gap-2">
          <span class="w-2 h-2 rounded-full bg-green-500 shadow-[0_0_8px_#22c55e]"></span>
          <span class="text-[10px] text-text-secondary font-semibold font-mono tracking-wider">Aegis Core API Active</span>
        </div>
        <div class="text-[10px] text-text-tertiary font-mono">
          ATI-PRO-2026 • Local Mode
        </div>
      </div>
    </div>

    <!-- RIGHT: Interactive Authentication Form -->
    <div class="w-full lg:w-1/2 flex items-center justify-center p-8 relative">
      <div class="absolute top-20 left-10 w-80 h-80 rounded-full bg-accent-blue/5 blur-[120px] pointer-events-none"></div>

      <!-- Auth Wrapper Card -->
      <div class="w-full max-w-md p-8 rounded-3xl bg-[#0b0f19]/80 border border-border-primary/60 backdrop-blur-md shadow-2xl relative z-10">
        <!-- Logo for mobile -->
        <div class="flex items-center gap-2.5 mb-8 lg:hidden">
          <Shield class="w-6 h-6 text-accent-blue" />
          <h1 class="font-logo text-sm font-black text-white tracking-widest uppercase">Aegis Threat Intel</h1>
        </div>

        <!-- FORM MODE: LOGIN -->
        <div v-if="formMode === 'login'">
          <div class="mb-6">
            <h2 class="text-xl font-black text-white tracking-wider">Establish SecOps Session</h2>
            <p class="text-xs text-text-tertiary mt-1">Authenticate credentials to unlock threat intelligence telemetry</p>
          </div>

          <!-- Alert Display -->
          <div
            v-if="loginError"
            class="mb-5 p-3.5 rounded-xl border border-red-500/20 bg-red-500/5 text-xs text-red-400 flex items-start gap-2.5 animate-pulse"
          >
            <ShieldAlert class="w-4 h-4 shrink-0 mt-0.5" />
            <span class="font-semibold leading-relaxed">{{ loginError }}</span>
          </div>

          <!-- OAuth Social Login Buttons -->
          <div class="grid grid-cols-2 gap-3 mb-5">
            <button
              type="button"
              class="flex items-center justify-center gap-2 py-2.5 rounded-xl border border-border-primary bg-bg-secondary/40 hover:bg-bg-tertiary/40 text-xs font-semibold text-text-secondary hover:text-white transition-all cursor-pointer"
            >
              <!-- Google Icon -->
              <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z" fill="#EA4335"/>
              </svg>
              <span>Google</span>
            </button>

            <button
              type="button"
              class="flex items-center justify-center gap-2 py-2.5 rounded-xl border border-border-primary bg-bg-secondary/40 hover:bg-bg-tertiary/40 text-xs font-semibold text-text-secondary hover:text-white transition-all cursor-pointer"
            >
              <!-- GitHub Icon -->
              <svg class="w-3.5 h-3.5" viewBox="0 0 24 24" fill="currentColor">
                <path d="M12 1.27a11 11 0 00-3.48 21.46c.55.09.73-.24.73-.53v-1.85c-3.03.66-3.67-1.46-3.67-1.46-.5-1.27-1.21-1.61-1.21-1.61-1-.68.08-.66.08-.66 1.1.08 1.68 1.13 1.68 1.13.98 1.68 2.58 1.19 3.22.9.1-.71.38-1.19.7-1.46-2.42-.27-4.96-1.2-4.96-5.38 0-1.19.43-2.17 1.13-2.93-.11-.27-.49-1.39.11-2.89 0 0 .91-.3 3 1.11A10.3 10.3 0 0112 7.61c.94.01 1.88.13 2.76.38 2.08-1.41 3-1.11 3-1.11.6 1.5.22 2.62.11 2.89.7.76 1.13 1.74 1.13 2.93 0 4.19-2.55 5.1-4.98 5.37.39.34.74 1 .74 2.02v3c0 .3.18.63.74.52A11 11 0 0012 1.27z"/>
              </svg>
              <span>GitHub</span>
            </button>
          </div>

          <div class="flex items-center gap-3 my-5">
            <div class="h-px bg-border-primary/20 flex-1"></div>
            <span class="text-[10px] text-text-tertiary font-mono uppercase tracking-wider shrink-0">or security credentials</span>
            <div class="h-px bg-border-primary/20 flex-1"></div>
          </div>

          <!-- Input Fields Form -->
          <form @submit.prevent="handleLogin" class="space-y-4">
            <div class="space-y-1.5">
              <div class="flex items-center justify-between">
                <label class="text-[10px] font-bold text-text-secondary uppercase tracking-wider font-mono">Operator ID</label>
                <!-- Autofill Demo Button -->
                <button
                  type="button"
                  @click="triggerAutofillDemo"
                  :disabled="isTypingDemo || isLoading"
                  class="text-[10px] font-bold text-accent-blue hover:text-accent-blue/80 transition-all font-mono flex items-center gap-1 cursor-pointer disabled:opacity-50"
                >
                  <span>⚡</span>
                  <span>{{ isTypingDemo ? 'Typing...' : 'Autofill Demo' }}</span>
                </button>
              </div>
              <div class="relative">
                <User class="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
                <input
                  v-model="username"
                  type="text"
                  placeholder="e.g. admin"
                  required
                  :disabled="isLoading || isTypingDemo"
                  class="w-full pl-10 pr-4 py-2.5 text-xs rounded-xl bg-bg-primary border border-border-primary text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-secondary focus:ring-1 focus:ring-border-secondary transition-all"
                />
              </div>
            </div>

            <div class="space-y-1.5">
              <label class="text-[10px] font-bold text-text-secondary uppercase tracking-wider font-mono">Security Key</label>
              <div class="relative">
                <Key class="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
                <input
                  v-model="password"
                  :type="showPassword ? 'text' : 'password'"
                  placeholder="••••••••••••"
                  required
                  :disabled="isLoading || isTypingDemo"
                  class="w-full pl-10 pr-10 py-2.5 text-xs rounded-xl bg-bg-primary border border-border-primary text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-secondary focus:ring-1 focus:ring-border-secondary transition-all"
                />
                <button
                  type="button"
                  class="absolute right-3 top-1/2 -translate-y-1/2 text-text-tertiary hover:text-white transition-all cursor-pointer"
                  @click="showPassword = !showPassword"
                >
                  <EyeOff v-if="showPassword" class="w-4 h-4" />
                  <Eye v-else class="w-4 h-4" />
                </button>
              </div>
            </div>

            <!-- Autocorrect Telemetry Console -->
            <div v-if="correctionLogs.length > 0" class="p-3.5 rounded-xl bg-accent-blue/5 border border-accent-blue/20 text-[10px] font-mono text-accent-blue space-y-1 mb-4">
              <div class="font-bold flex items-center gap-1.5 uppercase text-[9px] mb-1 tracking-wider">
                <Cpu class="w-3.5 h-3.5 animate-spin" />
                <span>Input Telemetry & Correction Console</span>
              </div>
              <div v-for="(log, idx) in correctionLogs" :key="idx" class="flex items-start gap-1">
                <span class="text-accent-blue/50">›</span>
                <span>{{ log }}</span>
              </div>
            </div>

            <!-- Login submit button -->
            <button
              type="submit"
              :disabled="isLoading || isTypingDemo"
              class="w-full py-3 mt-2 rounded-xl text-xs font-bold text-white transition-all bg-accent-blue border border-accent-blue/30 hover:bg-accent-blue/80 shadow-md shadow-accent-blue/15 hover:shadow-accent-blue/20 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Loader2 v-if="isLoading" class="w-4 h-4 animate-spin text-white" />
              <span>{{ isLoading ? 'Decryption Handshake...' : 'Establish Secure Connection' }}</span>
            </button>
          </form>

          <div class="text-center mt-6">
            <button
              type="button"
              class="text-[10px] font-bold text-text-tertiary hover:text-white tracking-wide transition-all uppercase font-mono cursor-pointer"
              @click="formMode = 'request'"
            >
              Request Access from Security Admin
            </button>
          </div>
        </div>

        <!-- FORM MODE: REQUEST ACCESS -->
        <div v-else-if="formMode === 'request'">
          <div class="mb-6">
            <button
              type="button"
              class="flex items-center gap-1.5 text-[10px] font-bold text-accent-blue hover:text-accent-blue/80 uppercase font-mono tracking-wider transition-all mb-4 cursor-pointer"
              @click="resetRequestForm"
            >
              <ArrowLeft class="w-3.5 h-3.5" />
              <span>Back to Login</span>
            </button>
            <h2 class="text-xl font-black text-white tracking-wider">Request Operator Access</h2>
            <p class="text-xs text-text-tertiary mt-1 font-sans">Submit justification to authorize your SecOps console access key</p>
          </div>

          <form @submit.prevent="handleRequestAccess" class="space-y-4">
            <div class="space-y-1.5">
              <label class="text-[10px] font-bold text-text-secondary uppercase tracking-wider font-mono">Full Name</label>
              <div class="relative">
                <User class="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
                <input
                  v-model="requestName"
                  type="text"
                  placeholder="John Doe"
                  required
                  :disabled="requestLoading"
                  class="w-full pl-10 pr-4 py-2.5 text-xs rounded-xl bg-bg-primary border border-border-primary text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-secondary focus:ring-1 focus:ring-border-secondary transition-all"
                />
              </div>
            </div>

            <div class="space-y-1.5">
              <label class="text-[10px] font-bold text-text-secondary uppercase tracking-wider font-mono">Organization Email</label>
              <div class="relative">
                <Mail class="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-text-tertiary" />
                <input
                  v-model="requestEmail"
                  type="email"
                  placeholder="jdoe@organization.com"
                  required
                  :disabled="requestLoading"
                  class="w-full pl-10 pr-4 py-2.5 text-xs rounded-xl bg-bg-primary border border-border-primary text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-secondary focus:ring-1 focus:ring-border-secondary transition-all"
                />
              </div>
            </div>

            <div class="space-y-1.5">
              <label class="text-[10px] font-bold text-text-secondary uppercase tracking-wider font-mono">SecOps Justification</label>
              <div class="relative">
                <Building class="absolute left-3.5 top-3 w-4 h-4 text-text-tertiary" />
                <textarea
                  v-model="requestJustification"
                  placeholder="Explain why you require access to ATI threat telemetry dashboards..."
                  required
                  rows="3"
                  :disabled="requestLoading"
                  class="w-full pl-10 pr-4 py-2.5 text-xs rounded-xl bg-bg-primary border border-border-primary text-text-primary placeholder:text-text-tertiary focus:outline-none focus:border-border-secondary focus:ring-1 focus:ring-border-secondary transition-all resize-none leading-relaxed"
                ></textarea>
              </div>
            </div>

            <button
              type="submit"
              :disabled="requestLoading"
              class="w-full py-3 mt-2 rounded-xl text-xs font-bold text-white transition-all bg-accent-blue border border-accent-blue/30 hover:bg-accent-blue/80 shadow-md shadow-accent-blue/15 flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
            >
              <Loader2 v-if="requestLoading" class="w-4 h-4 animate-spin text-white" />
              <span>{{ requestLoading ? 'Dispatching Operator Request...' : 'Dispatch Request' }}</span>
            </button>
          </form>
        </div>

        <!-- FORM MODE: REQUEST SUCCESS -->
        <div v-else-if="formMode === 'request-success'" class="text-center py-6 flex flex-col items-center">
          <div class="w-14 h-14 rounded-full bg-green-500/10 border border-green-500/30 flex items-center justify-center text-green-400 mb-5 animate-pulse">
            <Check class="w-7 h-7" />
          </div>
          
          <h2 class="text-lg font-black text-white tracking-wider">Request Dispatched</h2>
          <p class="text-xs text-text-secondary leading-relaxed mt-2 max-w-sm mx-auto">
            Your SecOps operator access application has been securely transmitted. A security administrator will email your activation security key shortly.
          </p>

          <button
            type="button"
            class="mt-6 px-6 py-2.5 rounded-xl border border-border-primary bg-bg-secondary/40 hover:bg-bg-tertiary/40 text-xs font-semibold text-text-secondary hover:text-white transition-all cursor-pointer"
            @click="resetRequestForm"
          >
            Return to Login Screen
          </button>
        </div>

        <!-- API status footer inside card -->
        <div class="border-t border-border-primary/40 mt-6 pt-4 flex items-center justify-between text-[9px] text-text-tertiary font-mono">
          <div class="flex items-center gap-1">
            <Server class="w-3.5 h-3.5" />
            <span>Connection Health:</span>
          </div>
          <div class="flex items-center gap-1.5 font-bold">
            <template v-if="apiHealth">
              <span class="w-1.5 h-1.5 rounded-full bg-green-500"></span>
              <span class="text-green-400">ONLINE</span>
            </template>
            <template v-else>
              <span class="w-1.5 h-1.5 rounded-full bg-red-500 animate-ping"></span>
              <span class="text-red-400">OFFLINE</span>
            </template>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
