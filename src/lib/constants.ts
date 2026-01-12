import { browser, dev } from '$app/environment';

// --------------------------------------------------------------------------
// ✅ Nebula AI 核心品牌配置
// --------------------------------------------------------------------------
export const APP_NAME = 'Nebula AI';
export const WEBUI_NAME = 'Nebula AI'; // 同时也定义这个，防止旧组件报错

// 🛠️ 【修复】直接定义版本号，不再依赖外部注入，消除红线报错
export const WEBUI_VERSION = 'v1.0.0';
export const WEBUI_BUILD_HASH = 'nebula-dev';
export const REQUIRED_OLLAMA_VERSION = '0.1.16';

// 为了兼容性，把旧变量名也指向这些值
export const APP_VERSION = WEBUI_VERSION;
export const APP_BUILD_HASH = WEBUI_BUILD_HASH;

// --------------------------------------------------------------------------
// 🔗 网络与 API 路径配置
// --------------------------------------------------------------------------
export const WEBUI_HOSTNAME = browser ? (dev ? `${location.hostname}:8080` : ``) : '';
export const WEBUI_BASE_URL = browser ? (dev ? `http://${WEBUI_HOSTNAME}` : ``) : ``;
export const WEBUI_API_BASE_URL = `${WEBUI_BASE_URL}/api/v1`;

export const OLLAMA_API_BASE_URL = `${WEBUI_BASE_URL}/ollama`;
export const OPENAI_API_BASE_URL = `${WEBUI_BASE_URL}/openai`;
export const AUDIO_API_BASE_URL = `${WEBUI_BASE_URL}/api/v1/audio`;
export const IMAGES_API_BASE_URL = `${WEBUI_BASE_URL}/api/v1/images`;
export const RETRIEVAL_API_BASE_URL = `${WEBUI_BASE_URL}/api/v1/retrieval`;

// --------------------------------------------------------------------------
// 📂 文件支持配置 (保留原版强大的文件支持)
// --------------------------------------------------------------------------
export const SUPPORTED_FILE_TYPE = [
    'application/epub+zip',
    'application/pdf',
    'text/plain',
    'text/csv',
    'text/xml',
    'text/html',
    'text/x-python',
    'text/css',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/octet-stream',
    'application/x-javascript',
    'text/markdown',
    'audio/mpeg',
    'audio/wav',
    'audio/ogg',
    'audio/x-m4a'
];

export const SUPPORTED_FILE_EXTENSIONS = [
    'md',
    'rst',
    'go',
    'py',
    'java',
    'sh',
    'bat',
    'ps1',
    'cmd',
    'js',
    'ts',
    'css',
    'cpp',
    'hpp',
    'h',
    'c',
    'cs',
    'htm',
    'html',
    'sql',
    'log',
    'ini',
    'pl',
    'pm',
    'r',
    'dart',
    'dockerfile',
    'env',
    'php',
    'hs',
    'hsc',
    'lua',
    'nginxconf',
    'conf',
    'm',
    'mm',
    'plsql',
    'perl',
    'rb',
    'rs',
    'db2',
    'scala',
    'bash',
    'swift',
    'vue',
    'svelte',
    'doc',
    'docx',
    'pdf',
    'csv',
    'txt',
    'xls',
    'xlsx',
    'pptx',
    'ppt',
    'msg'
];

export const PASTED_TEXT_CHARACTER_LIMIT = 1000;