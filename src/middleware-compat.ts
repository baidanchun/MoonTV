/* eslint-disable no-console */

/**
 * 兼容性中间件
 * 
 * 同时支持 MoonTV 旧版和 BolanTV 新版认证系统
 * 
 * 功能：
 * - 兼容旧版 Cookie 格式（password + signature）
 * - 支持新版 Token 机制（tokenId + refreshToken）
 * - 自动检测并适配不同格式
 */

import { NextRequest, NextResponse } from 'next/server';
import { 
  getAuthInfoFromCookie, 
  TOKEN_CONFIG, 
  isOldCookieFormat,
  isNewCookieFormat 
} from '@/lib/auth-compat';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // 跳过不需要认证的路径（兼容旧版）
  if (shouldSkipAuth(pathname)) {
    return NextResponse.next();
  }

  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';

  // 如果未配置密码，重定向到警告页面（兼容旧版）
  if (!process.env.PASSWORD) {
    const warningUrl = new URL('/warning', request.url);
    return warningUrl.pathname === pathname ? NextResponse.next() : NextResponse.redirect(warningUrl);
  }

  // 从 Cookie 获取认证信息（支持新旧格式）
  const authInfo = getAuthInfoFromCookie(request);

  if (!authInfo) {
    return handleAuthFailure(request, pathname);
  }

  // localstorage 模式：在 middleware 中完成验证（兼容旧版）
  if (storageType === 'localstorage') {
    if (!authInfo.password || authInfo.password !== process.env.PASSWORD) {
      return handleAuthFailure(request, pathname);
    }
    return NextResponse.next();
  }

  // 检测 Cookie 格式并分别处理
  if (isOldCookieFormat(authInfo)) {
    // 旧版格式：只验证签名（兼容 MoonTV）
    return handleOldFormatAuth(request, authInfo, pathname);
  } else if (isNewCookieFormat(authInfo)) {
    // 新版格式：验证 Token 机制（兼容 BolanTV）
    return handleNewFormatAuth(request, authInfo, pathname);
  }

  // 其他情况：认证失败
  return handleAuthFailure(request, pathname);
}

// 处理旧版 Cookie 格式（MoonTV）
async function handleOldFormatAuth(
  request: NextRequest,
  authInfo: any,
  pathname: string
): Promise<NextResponse> {
  console.log(`[Compat] Handling old format auth for ${authInfo.username}`);

  // 检查是否有用户名和签名（旧版要求）
  if (!authInfo.username || !authInfo.signature) {
    return handleAuthFailure(request, pathname);
  }

  // 验证签名（旧版）
  const isValidSignature = await verifyOldSignature(
    authInfo.username,
    authInfo.signature,
    process.env.PASSWORD || ''
  );

  if (!isValidSignature) {
    return handleAuthFailure(request, pathname);
  }

  // 签名验证通过，允许访问
  return NextResponse.next();
}

// 处理新版 Cookie 格式（BolanTV）
async function handleNewFormatAuth(
  request: NextRequest,
  authInfo: any,
  pathname: string
): Promise<NextResponse> {
  console.log(`[Compat] Handling new format auth for ${authInfo.username}`);

  // 检查必要字段（新版要求）
  if (!authInfo.username || !authInfo.role || !authInfo.signature || !authInfo.timestamp) {
    return handleAuthFailure(request, pathname);
  }

  // 强制要求新版 Cookie（必须包含 tokenId 和 refreshToken）
  if (!authInfo.tokenId || !authInfo.refreshToken || !authInfo.refreshExpires) {
    console.log(`[Compat] Old cookie format detected for ${authInfo.username}, forcing re-login`);
    return handleAuthFailure(request, pathname);
  }

  // 验证 Token 时间戳
  const ACCESS_TOKEN_AGE = TOKEN_CONFIG.ACCESS_TOKEN_AGE;
  const now = Date.now();
  const age = now - authInfo.timestamp;

  // 先检查 Refresh Token 是否过期
  if (now >= authInfo.refreshExpires) {
    console.log(`[Compat] Refresh token expired for ${authInfo.username}, redirecting to login`);
    return handleAuthFailure(request, pathname);
  }

  // Access Token 已过期
  if (age > ACCESS_TOKEN_AGE) {
    console.log(`[Compat] Access token expired for ${authInfo.username}`);
    
    // 对于 API 请求，返回 401，让前端拦截器刷新并重试
    if (pathname.startsWith('/api')) {
      return new NextResponse('Access token expired', { status: 401 });
    }
    
    // 对于页面请求，允许通过，让前端 TokenRefreshManager 在页面加载后刷新
    console.log(`[Compat] Allowing page request to pass, frontend will refresh token`);
  }

  // Access Token 未过期，验证签名（新版）
  const isValidSignature = await verifyNewSignature(
    authInfo.username,
    authInfo.role,
    authInfo.timestamp,
    authInfo.signature,
    process.env.PASSWORD || ''
  );

  if (!isValidSignature) {
    return handleAuthFailure(request, pathname);
  }

  // 签名验证通过，允许访问
  return NextResponse.next();
}

// 旧版签名验证（MoonTV）
async function verifyOldSignature(
  username: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(username);

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );

    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageData
    );
  } catch (error) {
    console.error('[Compat] Old signature verification failed:', error);
    return false;
  }
}

// 新版签名验证（BolanTV）
async function verifyNewSignature(
  username: string,
  role: string,
  timestamp: number,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);

  // 构造与生成签名时相同的数据结构
  const dataToSign = JSON.stringify({ username, role, timestamp });
  const messageData = encoder.encode(dataToSign);

  try {
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );

    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageData
    );
  } catch (error) {
    console.error('[Compat] New signature verification failed:', error);
    return false;
  }
}

// 处理认证失败的情况（兼容旧版）
function handleAuthFailure(
  request: NextRequest,
  pathname: string
): NextResponse {
  // 如果是 API 路由，返回 401 状态码（兼容旧版）
  if (pathname.startsWith('/api')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  // 否则重定向到登录页面（兼容旧版）
  const loginUrl = new URL('/login', request.url);
  // 保留完整的 URL，包括查询参数
  const fullUrl = `${pathname}${request.nextUrl.search}`;
  loginUrl.searchParams.set('redirect', fullUrl);
  return NextResponse.redirect(loginUrl);
}

// 判断是否需要跳过认证的路径（兼容旧版）
function shouldSkipAuth(pathname: string): boolean {
  const skipPaths = [
    '/_next',
    '/favicon.ico',
    '/robots.txt',
    '/manifest.json',
    '/icons/',
    '/logo.png',
    '/screenshot.png',
  ];

  return skipPaths.some((path) => pathname.startsWith(path));
}

// 配置 middleware 匹配规则（兼容旧版）
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|login|register|warning|api/login|api/register|api/logout|api/cron|api/server-config).*)',
  ],
};
