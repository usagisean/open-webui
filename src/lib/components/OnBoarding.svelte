<script lang="ts">
    import { getContext, onMount } from 'svelte';
    // [Sean Fix 1] 引入 Writable 类型，为了强转
    import type { Writable } from 'svelte/store';
    
    // [Sean Fix 2] 告诉编译器：这个 Context 返回的是一个 Writable Store，放心用 $ 去订阅
    const i18n = getContext<Writable<any>>('i18n');

    import { WEBUI_BASE_URL } from '$lib/constants';
    import ArrowRightCircle from './icons/ArrowRightCircle.svelte';

    export let show = true;
    export let getStartedHandler = () => {};

    function setLogoImage() {
        // [Sean Fix 3] 之前的类型断言保留
        const logo = document.getElementById('logo') as HTMLImageElement;

        if (logo) {
            const isDarkMode = document.documentElement.classList.contains('dark');

            if (isDarkMode) {
                const darkImage = new Image();
                darkImage.src = `${WEBUI_BASE_URL}/static/favicon.png`;

                darkImage.onload = () => {
                    logo.src = `${WEBUI_BASE_URL}/static/favicon.png`;
                    logo.style.filter = ''; 
                };

                darkImage.onerror = () => {
                    logo.style.filter = 'invert(1)'; 
                };
            }
        }
    }

    $: if (show) {
        setTimeout(() => setLogoImage(), 0);
    }
</script>

{#if show}
    <div class="w-full h-screen max-h-[100dvh] text-white relative bg-black overflow-hidden">
        
        <div class="fixed m-10 z-50">
            <div class="flex space-x-2">
                <div class="self-center">
                    <img
                        id="logo"
                        crossorigin="anonymous"
                        src="{WEBUI_BASE_URL}/static/favicon.png"
                        class="w-8 rounded-full opacity-80 hover:opacity-100 transition-opacity"
                        alt="logo"
                    />
                </div>
            </div>
        </div>

        <div class="absolute inset-0 z-0">
            <img 
                src="{WEBUI_BASE_URL}/static/hero-bg.jpg" 
                alt="Nebula Background" 
                class="w-full h-full object-cover opacity-80"
                on:error={(e) => {
                    const target = e.target as HTMLImageElement;
                    target.style.display = 'none';
                }} 
            />
        </div>

        <div
            class="w-full h-full absolute top-0 left-0 bg-gradient-to-t from-black via-black/40 to-transparent z-0"
        ></div>

        <div class="w-full h-full absolute top-0 left-0 backdrop-blur-[2px] bg-black/20 z-0"></div>

        <div class="relative w-full h-screen max-h-[100dvh] flex flex-col justify-end items-center pb-20 z-10">
            
            <div class="flex flex-col items-center space-y-6 mb-12 text-center">
                <h1 class="text-6xl lg:text-9xl font-bold font-secondary text-transparent bg-clip-text bg-gradient-to-b from-white via-gray-200 to-gray-500 drop-shadow-2xl tracking-tighter select-none">
                    Nebula AI
                </h1>

                <div class="text-xl lg:text-2xl font-light text-gray-300 tracking-[0.3em] opacity-90 uppercase">
                    {$i18n.t('wherever you are')}
                </div>

                <div class="flex items-center gap-4 mt-8 opacity-50">
                    <div class="h-[1px] w-16 bg-gradient-to-r from-transparent to-gray-400"></div>
                    <div class="text-[10px] lg:text-xs font-mono text-gray-400 uppercase tracking-[0.2em]">
                        ZIXIANG DIGITAL CORE
                    </div>
                    <div class="h-[1px] w-16 bg-gradient-to-l from-transparent to-gray-400"></div>
                </div>
            </div>

            <div class="flex flex-col items-center group cursor-pointer"
                 on:click={() => getStartedHandler()}
                 on:keydown={(e) => e.key === 'Enter' && getStartedHandler()}
                 role="button"
                 tabindex="0"
            >
                <button
                    aria-labelledby="get-started"
                    class="relative flex p-4 rounded-full bg-white/5 border border-white/10 backdrop-blur-md transition-all duration-500 group-hover:bg-white/15 group-hover:scale-110 group-hover:border-white/30 group-hover:shadow-[0_0_40px_rgba(255,255,255,0.1)]"
                >
                    <ArrowRightCircle className="size-8 text-gray-300 group-hover:text-white transition-colors" />
                </button>
                
                <div id="get-started" class="mt-4 font-mono text-xs font-medium text-gray-500 tracking-widest uppercase transition-colors group-hover:text-gray-300">
                    Initialize System
                </div>
            </div>

        </div>
    </div>
{/if}