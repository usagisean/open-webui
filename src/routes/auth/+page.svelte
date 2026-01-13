<script lang="ts">
	import DOMPurify from 'dompurify';
	import { marked } from 'marked';
	import { toast } from 'svelte-sonner';
	import { onMount, getContext, tick } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/stores';
	import { getBackendConfig } from '$lib/apis';
	import { ldapUserSignIn, getSessionUser, userSignIn, updateUserTimezone } from '$lib/apis/auths';
	import { WEBUI_API_BASE_URL, WEBUI_BASE_URL } from '$lib/constants';
	import { WEBUI_NAME, config, user, socket } from '$lib/stores';
	import { generateInitialsImage, getUserTimezone } from '$lib/utils';
	import Spinner from '$lib/components/common/Spinner.svelte';
	import OnBoarding from '$lib/components/OnBoarding.svelte';
	import SensitiveInput from '$lib/components/common/SensitiveInput.svelte'; // 确保引入

	const i18n = getContext('i18n');

	let loaded = false;
	let mode = $config?.features.enable_ldap ? 'ldap' : 'signin'; 
	
	let name = '';
	let email = '';
	let password = '';
	let confirmPassword = '';
	let ldapUsername = '';

	// --- 验证码状态 ---
	let countdown = 0;
	let timer: any = null;
	let verificationCode = '';
	let showVerificationInput = false;
    let isVerificationLoading = false;

	// 密码显示状态
	let showPassword = false;
    let showConfirmPassword = false;

	const setSessionUser = async (sessionUser, redirectPath: string | null = null) => {
		if (sessionUser) {
			if (sessionUser.role === 'pending') return;
			toast.success($i18n.t(`You're now logged in.`));
			if (sessionUser.token) localStorage.token = sessionUser.token;
			$socket.emit('user-join', { auth: { token: sessionUser.token } });
			await user.set(sessionUser);
			await config.set(await getBackendConfig());

			const timezone = getUserTimezone();
			if (sessionUser.token && timezone) updateUserTimezone(sessionUser.token, timezone);

			if (!redirectPath) redirectPath = $page.url.searchParams.get('redirect') || '/';
			goto(redirectPath);
			localStorage.removeItem('redirectPath');
		}
	};

	const startCountdown = () => {
		countdown = 60;
		if (timer) clearInterval(timer);
		timer = setInterval(() => {
			countdown -= 1;
			if (countdown <= 0) {
				clearInterval(timer);
				countdown = 0;
			}
		}, 1000);
	};

	const sendVerificationCode = async () => {
        // --- 1. 邮箱格式校验 (正则) ---
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!email || !emailPattern.test(email)) {
            toast.error($i18n.t('Please enter a valid email address.'));
            return;
        }

        // --- 2. 密码一致性校验 ---
        if (password !== confirmPassword) {
            toast.error($i18n.t('Passwords do not match.'));
            return;
        }

        // --- 3. 密码强度校验 (已修改为 8 位) ---
        if (password.length < 8) {
            toast.error('Password must be at least 8 characters.');
            return;
        }
        // 强制密码必须包含字母和数字
        const complexityPattern = /^(?=.*[A-Za-z])(?=.*\d)/;
        if (!complexityPattern.test(password)) {
             toast.error('Password must contain both letters and numbers.');
             return;
        }
        isVerificationLoading = true;

		try {
            // 注意：这里调用 signup 接口。如果后端返回 403 Forbidden，说明 ENABLE_SIGNUP=False
			const res = await fetch(`${WEBUI_API_BASE_URL}/auths/signup`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					name: name || email.split('@')[0],
					email: email,
					password: password,
					profile_image_url: generateInitialsImage(name || email)
				})
			});

			const data = await res.json();

			if (res.status === 401 && data.detail === 'VERIFICATION_REQUIRED') {
				toast.success($i18n.t('Verification code sent to your email.'));
				showVerificationInput = true;
				startCountdown();
			} else if (!res.ok) {
                // 处理后端报错
                if (res.status === 403) {
                    toast.error("Registration is disabled by administrator (ENABLE_SIGNUP=False).");
                } else {
				    throw data.detail;
                }
			} else {
				await setSessionUser(data);
			}
		} catch (error) {
			toast.error(`${error}`);
		} finally {
            isVerificationLoading = false;
        }
	};

    const completeSignUp = async () => {
        if (!verificationCode || verificationCode.length !== 6) {
             toast.error($i18n.t('Please enter a valid 6-digit code.'));
             return;
        }
        isVerificationLoading = true;
        try {
            const res = await fetch(`${WEBUI_API_BASE_URL}/auths/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email, code: verificationCode })
            });
            const data = await res.json();
            if (!res.ok) throw data.detail;
            await setSessionUser(data);
        } catch (error) {
            toast.error(`${error}`);
        } finally {
            isVerificationLoading = false;
        }
    };

	const signInHandler = async () => {
		const sessionUser = await userSignIn(email, password).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		await setSessionUser(sessionUser);
	};

	const ldapSignInHandler = async () => {
		const sessionUser = await ldapUserSignIn(ldapUsername, password).catch((error) => {
			toast.error(`${error}`);
			return null;
		});
		await setSessionUser(sessionUser);
	};

	const submitHandler = async () => {
		if (mode === 'ldap') await ldapSignInHandler();
		else if (mode === 'signin') await signInHandler();
	};

    // 找回密码
    let forgotStep = 1;
    let resetCode = '';
    let newPassword = '';
    const sendResetCode = async () => {
         try {
            const res = await fetch(`${WEBUI_API_BASE_URL}/auths/password/reset/code`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            if (!res.ok) throw (await res.json()).detail;
            toast.success($i18n.t('Reset code sent to your email'));
            forgotStep = 2;
        } catch (e) { toast.error(`${e}`); }
    };

    const resetPasswordSubmit = async () => {
        try {
            const res = await fetch(`${WEBUI_API_BASE_URL}/auths/password/reset/verify`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, code: resetCode, new_password: newPassword })
            });
            if (!res.ok) throw (await res.json()).detail;
            toast.success($i18n.t('Password reset successfully. Please login.'));
            mode = 'signin';
        } catch (e) { toast.error(`${e}`); }
    };

	const oauthCallbackHandler = async () => {
		function getCookie(name) {
			const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()[\]\\/+^])/g, '\\$1') + '=([^;]*)'));
			return match ? decodeURIComponent(match[1]) : null;
		}
		const token = getCookie('token');
		if (!token) return;
		const sessionUser = await getSessionUser(token).catch((error) => { toast.error(`${error}`); return null; });
		if (!sessionUser) return;
		localStorage.token = token;
		await setSessionUser(sessionUser, localStorage.getItem('redirectPath') || null);
	};

	let onboarding = false;
	onMount(async () => {
        showVerificationInput = false;
        countdown = 0;
		const redirectPath = $page.url.searchParams.get('redirect');
		if ($user !== undefined) goto(redirectPath || '/');
		else if (redirectPath) localStorage.setItem('redirectPath', redirectPath);

		const error = $page.url.searchParams.get('error');
		if (error) toast.error(error);

		await oauthCallbackHandler();
		loaded = true;
		if (($config?.features.auth_trusted_header ?? false) || $config?.features.auth === false) await signInHandler();
		else onboarding = $config?.onboarding ?? false;
	});
</script>

<svelte:head>
	<title>{`${$WEBUI_NAME}`}</title>
</svelte:head>

<OnBoarding bind:show={onboarding} getStartedHandler={() => { onboarding = false; mode = 'signup'; }} />

<div class="fixed inset-0 z-0 bg-[#050505] overflow-hidden">
    <img src="/assets/images/earth.jpg" alt="Background" class="w-full h-full object-cover opacity-30 scale-105 pointer-events-none" />
    <div class="absolute inset-0 bg-gradient-to-r from-black via-black/60 to-transparent"></div>
</div>

<div class="relative w-full min-h-screen flex z-10 text-white font-primary overflow-hidden">
	<div class="w-full absolute top-0 left-0 right-0 h-8 drag-region z-50" />

	{#if loaded}
		<main class="w-full flex flex-col lg:flex-row min-h-screen items-center justify-center lg:justify-between">
            
            <div class="hidden lg:flex flex-1 flex-col justify-center px-16 xl:px-24 space-y-8 h-full">
				<div class="space-y-4">
					<img src="/static/favicon.png" class="size-20 rounded-2xl shadow-2xl mb-8 ring-1 ring-white/10" alt="Logo" />
					<h1 class="text-6xl font-black tracking-tighter leading-[1.1]">
						Nebula AI <br/>
						<span class="bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-indigo-600">
							The Hub of Minds.
						</span>
					</h1>
					<p class="text-xl text-gray-400 max-w-lg leading-relaxed font-light">
						{$i18n.t('Generate images, process documents, and chat with private models in one secure cloud.')}
					</p>
				</div>
			</div>

            <div class="flex-1 flex items-center justify-center p-4 w-full h-full">
                <div class="w-full max-w-[420px] bg-[#09090b] border border-white/10 rounded-[1.5rem] shadow-2xl relative flex flex-col max-h-[90vh]">
                    
                    <div class="absolute top-0 left-1/2 -translate-x-1/2 w-3/4 h-1 bg-gradient-to-r from-transparent via-blue-500 to-transparent opacity-50 blur-sm pointer-events-none z-20"></div>

                    <div class="px-8 pt-8 pb-4 text-center shrink-0 z-10 bg-[#09090b]">
						<h2 class="text-2xl font-bold tracking-tight mb-1 text-white">
							{#if mode === 'signup'}{$i18n.t('Create Account')}
							{:else if mode === 'forgot'}{$i18n.t('Reset Password')}
							{:else if mode === 'ldap'}{$i18n.t('LDAP Login')}
							{:else}{$i18n.t('Welcome back')}
							{/if}
						</h2>
                        <p class="text-gray-500 text-xs">
                            {#if mode === 'signup'}Enter your details to get started.
                            {:else if mode === 'forgot'}We'll verify your email first.
                            {:else}Please enter your details to sign in.{/if}
                        </p>
					</div>

                    <div class="px-8 pb-8 overflow-y-auto custom-scrollbar flex-1">
                        <form on:submit|preventDefault={submitHandler} class="flex flex-col space-y-3">
                            
                            {#if mode === 'signup'}
                                <div>
                                    <label for="name" class="block text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1 ml-1">Name</label>
                                    <input bind:value={name} type="text" class="nebula-input" placeholder="Your Name" required />
                                </div>
                            {/if}

                            {#if mode === 'ldap'}
                                <div>
                                    <label for="username" class="block text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1 ml-1">Username</label>
                                    <input bind:value={ldapUsername} type="text" class="nebula-input" placeholder="LDAP Username" required />
                                </div>
                            {:else}
                                <div>
                                    <label for="email" class="block text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1 ml-1">Email</label>
                                    <input bind:value={email} type="email" class="nebula-input" placeholder="name@example.com" required disabled={mode === 'forgot' && forgotStep === 2} />
                                </div>
                            {/if}

                            {#if mode !== 'forgot'}
                                <div>
                                    <div class="flex justify-between items-center mb-1 ml-1">
                                        <label for="password" class="block text-[10px] font-bold text-gray-400 uppercase tracking-widest">Password</label>
                                        {#if mode === 'signin' || mode === 'ldap'}
                                            <button type="button" on:click={() => { mode = 'forgot'; forgotStep = 1; }} class="text-[10px] font-bold text-blue-500 hover:text-blue-400">FORGOT?</button>
                                        {/if}
                                    </div>
                                    <div class="relative">
                                        <input bind:value={password} type={showPassword ? "text" : "password"} class="nebula-input pr-10" placeholder="••••••••" required />
                                        <button type="button" class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white" on:click={() => showPassword = !showPassword}>
                                            {#if showPassword}
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="size-4"><path fill-rule="evenodd" d="M3.28 2.22a.75.75 0 0 0-1.06 1.06l14.5 14.5a.75.75 0 1 0 1.06-1.06l-1.745-1.745A10.02 10.02 0 0 0 10 17.75c-5.385 0-9.75-4.365-9.75-9.75a9.9 9.9 0 0 1 2.67-6.36l-.64-.64ZM15.894 13.772l-1.47-1.47a2.5 2.5 0 0 0-3.328-3.328l-1.47-1.47A5.002 5.002 0 0 1 12.5 10a5 5 0 0 1 3.394 3.772Zm2.256-2.26a9.967 9.967 0 0 0 1.6-4.762c0-5.385-4.365-9.75-9.75-9.75a9.957 9.957 0 0 0-4.99 1.336l1.583 1.583A7.508 7.508 0 0 1 10 2.25c4.013 0 7.25 3.237 7.25 7.25 0 .89-.155 1.73-.435 2.508l1.335 1.334Z" clip-rule="evenodd" /></svg>
                                            {:else}
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="size-4"><path d="M10 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" /><path fill-rule="evenodd" d="M.664 10.59a1.651 1.651 0 0 1 0-1.186A10.004 10.004 0 0 1 10 3c4.257 0 7.893 2.66 9.336 6.41.147.381.146.804 0 1.186A10.004 10.004 0 0 1 10 17c-4.257 0-7.893-2.66-9.336-6.41ZM14 10a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z" clip-rule="evenodd" /></svg>
                                            {/if}
                                        </button>
                                    </div>
                                </div>
                            {/if}

                            {#if mode === 'signup'}
                                <div class="animate-in fade-in slide-in-from-top-1">
                                    <label for="confirm-password" class="block text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1 ml-1">Confirm Password</label>
                                    <div class="relative">
                                        <input bind:value={confirmPassword} type={showConfirmPassword ? "text" : "password"} class="nebula-input pr-10" placeholder="Confirm ••••••••" required />
                                        {#if confirmPassword && password === confirmPassword}
                                            <div class="absolute right-3 top-1/2 -translate-y-1/2 text-green-500">
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="size-4"><path fill-rule="evenodd" d="M10 18a8 8 0 1 0 0-16 8 8 0 0 0 0 16Zm3.857-9.809a.75.75 0 0 0-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 1 0-1.06 1.061l2.5 2.5a.75.75 0 0 0 1.137-.089l4-5.5Z" clip-rule="evenodd" /></svg>
                                            </div>
                                        {:else if confirmPassword}
                                             <button type="button" class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white" on:click={() => showConfirmPassword = !showConfirmPassword}>
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor" class="size-4"><path d="M10 12.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Z" /><path fill-rule="evenodd" d="M.664 10.59a1.651 1.651 0 0 1 0-1.186A10.004 10.004 0 0 1 10 3c4.257 0 7.893 2.66 9.336 6.41.147.381.146.804 0 1.186A10.004 10.004 0 0 1 10 17c-4.257 0-7.893-2.66-9.336-6.41ZM14 10a4 4 0 1 1-8 0 4 4 0 0 1 8 0Z" clip-rule="evenodd" /></svg>
                                            </button>
                                        {/if}
                                    </div>
                                </div>

                                <div class="pt-1">
                                    {#if !showVerificationInput}
                                        <button 
                                            type="button" 
                                            class="nebula-btn-secondary"
                                            on:click={sendVerificationCode}
                                            disabled={isVerificationLoading || (password !== confirmPassword) || !password}
                                        >
                                            {#if isVerificationLoading} <Spinner className="size-4" /> {:else} {$i18n.t('Get Verification Code')} {/if}
                                        </button>
                                    {:else}
                                        <div class="animate-in fade-in slide-in-from-bottom-2">
                                            <div class="mb-2">
                                                <input bind:value={verificationCode} type="text" maxlength="6" class="nebula-input text-center tracking-[0.5em] font-mono text-lg bg-white/10 border-blue-500/50" placeholder="000000" />
                                            </div>
                                            <div class="flex justify-between items-center text-[10px] px-1">
                                                <span class="text-green-500">Sent to email</span>
                                                {#if countdown > 0}
                                                    <span class="text-gray-500">Resend in {countdown}s</span>
                                                {:else}
                                                    <button type="button" class="text-blue-500 hover:underline font-bold" on:click={sendVerificationCode}>Resend</button>
                                                {/if}
                                            </div>
                                        </div>
                                    {/if}
                                </div>
                            {/if}

                            {#if mode === 'forgot' && forgotStep === 2}
                                <div class="space-y-3 animate-in fade-in">
                                    <input bind:value={resetCode} type="text" class="nebula-input text-center tracking-widest" placeholder="6-digit code" required />
                                    <input bind:value={newPassword} type="password" class="nebula-input" placeholder="New Password" required />
                                </div>
                            {/if}

                            <div class="pt-2">
                                {#if mode === 'signin' || mode === 'ldap'}
                                    <button class="nebula-btn-primary" type="submit">{$i18n.t('Sign In')}</button>
                                {:else if mode === 'signup'}
                                    {#if showVerificationInput}
                                        <button class="nebula-btn-primary" type="button" on:click={completeSignUp} disabled={isVerificationLoading}>
                                            {#if isVerificationLoading}<Spinner className="size-4" />{:else}{$i18n.t('Create Account')}{/if}
                                        </button>
                                    {/if}
                                {:else if mode === 'forgot'}
                                    <button class="nebula-btn-primary" type="button" on:click={() => forgotStep === 1 ? sendResetCode() : resetPasswordSubmit()}>
                                        {forgotStep === 1 ? $i18n.t('Send Reset Code') : $i18n.t('Reset Password')}
                                    </button>
                                {/if}
                            </div>
                        </form>

                        {#if Object.keys($config?.oauth?.providers ?? {}).length > 0 && mode !== 'forgot' && !showVerificationInput}
                            <div class="relative my-4">
                                <div class="absolute inset-0 flex items-center"><div class="w-full border-t border-white/10"></div></div>
                                <div class="relative flex justify-center text-[10px] uppercase font-bold tracking-widest"><span class="bg-[#09090b] px-2 text-gray-600">Or continue with</span></div>
                            </div>

                            <div class="grid grid-cols-1 gap-2">
                                {#if $config?.oauth?.providers?.google}
                                    <button class="nebula-btn-oauth" on:click={() => window.location.href = `${WEBUI_BASE_URL}/oauth/google/login`}>
                                        <svg class="size-4 mr-2" viewBox="0 0 48 48"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>
                                        Google
                                    </button>
                                {/if}
                                {#if $config?.oauth?.providers?.github}
                                    <button class="nebula-btn-oauth" on:click={() => window.location.href = `${WEBUI_BASE_URL}/oauth/github/login`}>
                                        <svg class="size-4 mr-2" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.92 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57C20.565 21.795 24 17.31 24 12c0-6.63-5.37-12-12-12z"/></svg>
                                        GitHub
                                    </button>
                                {/if}
                                {#if $config?.oauth?.providers?.microsoft}
                                    <button class="nebula-btn-oauth" on:click={() => window.location.href = `${WEBUI_BASE_URL}/oauth/microsoft/login`}>Microsoft</button>
                                {/if}
                                {#if $config?.oauth?.providers?.oidc}
                                    <button class="nebula-btn-oauth" on:click={() => window.location.href = `${WEBUI_BASE_URL}/oauth/oidc/login`}>SSO / OIDC</button>
                                {/if}
                            </div>
                        {/if}

                        <div class="mt-6 text-center text-xs">
                            {#if mode === 'signin' || mode === 'ldap'}
                                <span class="text-gray-500">Don't have an account? </span>
                                <button class="text-white font-bold hover:underline" on:click={() => { mode = 'signup'; showVerificationInput = false; }}>Sign up</button>
                            {:else if mode === 'signup'}
                                <span class="text-gray-500">Already have an account? </span>
                                <button class="text-white font-bold hover:underline" on:click={() => { mode = 'signin'; showVerificationInput = false; }}>Sign in</button>
                            {:else}
                                <button class="text-gray-500 hover:text-white" on:click={() => { mode = 'signin'; forgotStep = 1; }}>← Back to login</button>
                            {/if}
                        </div>
					</div>
				</div>
			</div>
		</main>
	{/if}
</div>

<style>
    :global(body) { background-color: #050505; color: white; }
    .drag-region { -webkit-app-region: drag; }

    /* 滚动条美化 */
    .custom-scrollbar::-webkit-scrollbar { width: 4px; }
    .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
    .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, 0.1); border-radius: 4px; }
    .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }

    .nebula-input {
        width: 100%;
        background-color: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 0.75rem;
        padding: 0.75rem 1rem; /* 更紧凑的 padding: py-3 */
        font-size: 0.875rem; /* text-sm */
        color: white;
        transition: all 0.2s;
        outline: none;
    }
    .nebula-input:focus {
        background-color: rgba(255, 255, 255, 0.08);
        border-color: #3b82f6;
        box-shadow: 0 0 0 1px rgba(59, 130, 246, 0.2);
    }
    .nebula-input:disabled { opacity: 0.5; cursor: not-allowed; }

    .nebula-btn-primary {
        width: 100%;
        background-color: white;
        color: black;
        font-weight: 800;
        padding: 0.75rem;
        border-radius: 0.75rem;
        transition: all 0.2s;
        font-size: 0.875rem;
    }
    .nebula-btn-primary:hover:not(:disabled) { transform: scale(0.98); background-color: #e5e5e5; }
    .nebula-btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }

    .nebula-btn-secondary {
        width: 100%;
        background-color: rgba(255, 255, 255, 0.1);
        color: white;
        font-weight: 700;
        padding: 0.75rem;
        border-radius: 0.75rem;
        border: 1px solid rgba(255,255,255,0.05);
        transition: all 0.2s;
        font-size: 0.75rem; /* text-xs */
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .nebula-btn-secondary:hover:not(:disabled) { background-color: rgba(255, 255, 255, 0.2); }
    .nebula-btn-secondary:disabled { opacity: 0.5; cursor: not-allowed; }

    .nebula-btn-oauth {
        display: flex;
        justify-content: center;
        align-items: center;
        width: 100%;
        background-color: rgba(255, 255, 255, 0.03);
        border: 1px solid rgba(255, 255, 255, 0.1);
        color: #9ca3af;
        font-weight: 600;
        font-size: 0.75rem;
        padding: 0.6rem;
        border-radius: 0.75rem;
        transition: all 0.2s;
    }
    .nebula-btn-oauth:hover { background-color: rgba(255, 255, 255, 0.08); color: white; }
</style>