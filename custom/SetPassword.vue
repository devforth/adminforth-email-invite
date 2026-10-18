<template>
  <div class="relative flex items-center justify-center min-h-screen bg-lightHtml dark:bg-darkHtml w-screen h-screen"
    :style="coreStore.config?.loginBackgroundImage && backgroundPosition === 'over' ? {
      'background-image': 'url(' + loadFile(coreStore.config?.loginBackgroundImage) + ')',
      'background-size': 'cover',
      'background-position': 'center',
      'background-blend-mode': coreStore.config?.removeBackgroundBlendMode ? 'normal' : 'darken'
    }: {}"
  >

    <img v-if="coreStore.config?.loginBackgroundImage && backgroundPosition !== 'over'"
      :src="loadFile(coreStore.config?.loginBackgroundImage)"
      class="position-absolute top-0 left-0 h-screen object-cover w-0"
      :class="{
        '1/2': 'md:w-1/2',
        '1/3': 'md:w-1/3',
        '2/3': 'md:w-2/3',
        '3/4': 'md:w-3/4',
        '2/5': 'md:w-2/5',
        '3/5': 'md:w-3/5',
      }[backgroundPosition]"
    />

    <!-- Main modal -->
    <div id="authentication-modal" tabindex="-1"
      class="af-set-password-modal overflow-y-auto flex flex-grow
      overflow-x-hidden z-50 min-w-[350px]  justify-center items-center md:inset-0 h-[calc(100%-1rem)] max-h-full">
      <div class="relative flex w-full max-h-full justify-center p-4">
        <DialogPanel
          class="af-login-popup af-auth-card"
          :title="header.title"
          :subtitle="header.subtitle"
          :error="tokenValid && !passwordSet ? validationError || error : null"
          :classes="AUTH_CARD_CLASSES"
        >
          <template #icon><IconUserPlus /></template>

          <div v-if="loading" class="flex justify-center py-6">
            <Spinner class="w-8 h-8" />
          </div>

          <p v-else-if="!tokenValid" role="alert" class="af-alert-error flex items-start gap-2.5 rounded-lg border border-lightDangerBorder bg-lightDangerSoft px-3.5 py-3 text-sm leading-5 text-lightDanger dark:border-darkDangerBorder dark:bg-darkDangerSoft dark:text-darkDanger">
            <IconCircleAlert class="w-5 h-5 shrink-0" />
            {{ $t('This invitation link is invalid or has expired. Ask your administrator to send a new one.') }}
          </p>

          <template v-else-if="passwordSet">
            <p role="status" class="af-alert-success flex items-start gap-2.5 rounded-lg border border-lightSuccessBorder bg-lightSuccessSoft px-3.5 py-3 text-sm leading-5 text-lightSuccess dark:border-darkSuccessBorder dark:bg-darkSuccessSoft dark:text-darkSuccess">
              <IconCircleCheck class="w-5 h-5 shrink-0" />
              {{ isUserLoggedIn ? $t('Password set successfully to your new account.') : $t('Password set successfully! Log in with your email and the new password.') }}
            </p>
            <p v-if="isUserLoggedIn" class="text-sm text-lightLoginViewTextColor dark:text-darkLoginViewTextColor">
              {{ $t('You are still logged in to another account. Stay in it, or log out to log in to the new one.') }}
            </p>
          </template>

          <template v-else>
            <!-- enter is handled on the wrapper: Input spreads attrs on both its root and the input -->
            <div class="af-password-field" @keydown.enter="passwordConfirmationInput!.focus()">
              <label for="password" class="block mb-2 text-sm font-medium text-lightLoginViewTextColor dark:text-darkLoginViewTextColor">{{ $t('Password') }}</label>
              <Input
                v-model="password"
                id="password"
                name="password"
                type="password"
                passwordToggle
                autocomplete="new-password"
                :placeholder="$t('Enter your password')"
                :invalid="Boolean(validationError)"
                fullWidth
                required
              />
            </div>
            <div class="af-password-field" @keydown.enter="setPassword">
              <label for="password_confirmation" class="block mb-2 text-sm font-medium text-lightLoginViewTextColor dark:text-darkLoginViewTextColor">{{ $t('Confirm password') }}</label>
              <Input
                ref="passwordConfirmationInput"
                v-model="passwordConfirmation"
                id="password_confirmation"
                name="password_confirmation"
                type="password"
                passwordToggle
                autocomplete="new-password"
                :placeholder="$t('Confirm your password')"
                :invalid="Boolean(validationError)"
                fullWidth
                required
              />
            </div>
          </template>

          <template v-if="!loading" #footer>
            <LinkButton v-if="!tokenValid" to="/login" variant="secondary" class="whitespace-nowrap">{{ $t('Go to login') }}</LinkButton>
            <template v-else-if="passwordSet && isUserLoggedIn">
              <Button variant="secondary" class="whitespace-nowrap" @click="logoutUser">{{ $t('Log out') }}</Button>
              <Button class="whitespace-nowrap" @click="stayLoggedIn">{{ $t('Stay logged in') }}</Button>
            </template>
            <LinkButton v-else-if="passwordSet" to="/login" class="whitespace-nowrap">{{ $t('Go to login') }}</LinkButton>
            <Button
              v-else
              :loader="inProgress"
              :disabled="inProgress || (validationRunning && validationError)"
              class="whitespace-nowrap"
              @click="setPassword"
            >
              {{ $t('Set password') }}
            </Button>
          </template>
        </DialogPanel>
      </div>
    </div>

  </div>
</template>

<script setup lang="ts">
import { onMounted, ref, computed, Ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { useCoreStore } from '@/stores/core';
import { useUserStore } from '@/stores/user';
import { callAdminForthApi, loadFile, applyRegexValidation } from '@/utils';
import { useRoute, useRouter } from 'vue-router';
import { IconCircleAlert, IconCircleCheck, IconUserPlus } from '@iconify-prerendered/vue-lucide';
import { Button, DialogPanel, Input, LinkButton, Spinner } from '@/afcl';

const { t } = useI18n();

const inProgress = ref(false);
const loading = ref(true);
const tokenValid = ref(false);
const passwordSet = ref(false);

const userStore = useUserStore();
const coreStore = useCoreStore();

// class names apps restyle the card by, kept from the former AuthCard
const AUTH_CARD_CLASSES = {
  header: 'af-auth-card-header',
  icon: 'af-auth-card-icon',
  titleWrap: 'af-auth-card-title-wrap',
  title: 'af-auth-card-title',
  subtitle: 'af-auth-card-subtitle',
  body: 'af-auth-card-body',
  error: 'af-auth-card-error',
  footer: 'af-auth-card-footer',
};
const passwordConfirmationInput = ref<InstanceType<typeof Input> | null>(null);
const password = ref("");
const passwordConfirmation = ref("");

const route = useRoute();
const router = useRouter();

const validationRunning = ref(false);
const error = ref(null);

const isUserLoggedIn = localStorage.getItem('isAuthorized') === 'true';

const header = computed(() => {
  const brand = coreStore.config?.brandName;
  if (passwordSet.value) {
    return {
      title: t('Password set'),
      subtitle: isUserLoggedIn ? t('Your new {brand} account is ready', { brand }) : t('Your {brand} account is ready', { brand }),
    };
  }
  return { title: t('Set your password'), subtitle: t('Create a password for your {brand} account', { brand }) };
});

const backgroundPosition = computed(() => {
  return coreStore.config?.loginBackgroundPosition || '1/2';
});

const passwordField = computed(
  () => route.meta.passwordField
)


function checkPassword() {

if (!password.value || !passwordConfirmation.value) {
  return 'Please enter both password and password confirmation';
}
if (password.value !== passwordConfirmation.value) {
  return 'Passwords do not match';
}

if (password.value.length < passwordField.value.minLength) {
  return `Password must be at least ${passwordField.value.minLength} characters long`;
}

if (password.value.length > passwordField.value.maxLength) {
  return `Password must be at most ${passwordField.value.maxLength} characters long`;
}

if (passwordField.value.validation) {
  const valError = applyRegexValidation(password.value, passwordField.value.validation);
  if (valError) {
    return valError;
  }
}

return null;
}

const validationError = computed(() => {
  if (validationRunning.value) {
    return checkPassword();
  }
  return null;
});

onMounted(async () => {
  loading.value = true;
  await coreStore.getPublicConfig();

  // Check if token is present and valid
  const token = route.query.token;
  if (token) {
    tokenValid.value = true;
  } else {
    tokenValid.value = false;
  }

  loading.value = false;
});

async function setPassword() {
  error.value = null;

  if (checkPassword()) {
    validationRunning.value = true;
    return;
  } else {
    validationRunning.value = false;
  }

  inProgress.value = true;
  const resp = await callAdminForthApi({
    path: `/plugin/${route.meta.pluginInstanceId}/set-password`,
    method: 'POST',
    body: {
      token: route.query.token,
      password: password.value,
    }
  });
  inProgress.value = false;

  if (resp.error) {
    error.value = resp.error;
    if (resp.error.includes('Invalid') || resp.error.includes('expired')) {
      tokenValid.value = false;
    }
  } else {
    error.value = null;
    passwordSet.value = true;
  }
}

async function logoutUser() {
  userStore.unauthorize();
  await userStore.logout();
  router.push({ name: 'login' })
}

function stayLoggedIn() {
  coreStore.fetchMenuAndResource();
  if (route.query.next) {
    router.push(route.query.next.toString());
  } else {
    router.push({ name: 'home' });
  }
}
</script>
