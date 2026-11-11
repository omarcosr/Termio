//! The Android framework from the core, over JNI. Tarve hands a plugin no JNIEnv, but the core
//! lives in the activity's process: it finds the process' Java VM and the application itself.

use jni::objects::{JByteArray, JClass, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use std::sync::OnceLock;

type GetCreatedVms = unsafe extern "system" fn(*mut *mut jni::sys::JavaVM, jni::sys::jsize, *mut jni::sys::jsize) -> jni::sys::jint;

/// The process' VM: `JNI_GetCreatedJavaVMs` from libnativehelper (Android 12+) or libart.
fn vm() -> Result<&'static JavaVM, String> {
    static VM: OnceLock<Result<JavaVM, String>> = OnceLock::new();
    VM.get_or_init(|| {
        for library in [c"libnativehelper.so", c"libart.so"] {
            // SAFETY: both are loaded in every app process; RTLD_NOLOAD only finds them.
            let handle = unsafe { libc::dlopen(library.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
            if handle.is_null() {
                continue;
            }
            // SAFETY: a live handle and a NUL-terminated name.
            let symbol = unsafe { libc::dlsym(handle, c"JNI_GetCreatedJavaVMs".as_ptr()) };
            if symbol.is_null() {
                continue;
            }
            // SAFETY: the symbol has this signature (jni.h).
            let get: GetCreatedVms = unsafe { std::mem::transmute(symbol) };
            let mut raw = std::ptr::null_mut();
            let mut count = 0;
            // SAFETY: room for one VM; Android runs exactly one.
            if unsafe { get(&mut raw, 1, &mut count) } == 0 && count > 0 && !raw.is_null() {
                // SAFETY: a VM the runtime handed out, alive for the life of the process.
                return unsafe { JavaVM::from_raw(raw) }.map_err(|error| error.to_string());
            }
        }
        Err("the Java VM is not reachable".into())
    })
    .as_ref()
    .map_err(Clone::clone)
}

/// Runs `body` with this thread attached to the VM; a Java exception becomes its message.
pub fn with_env<T>(body: impl FnOnce(&mut JNIEnv<'_>) -> jni::errors::Result<T>) -> Result<T, String> {
    let mut env = vm()?.attach_current_thread_permanently().map_err(|error| error.to_string())?;
    let result = env.with_local_frame(32, |env| body(env));
    if env.exception_check().unwrap_or(false) {
        let message = env
            .exception_occurred()
            .ok()
            .and_then(|throwable| {
                let _ = env.exception_clear();
                env.call_method(&throwable, "toString", "()Ljava/lang/String;", &[]).ok()?.l().ok()
            })
            .and_then(|text| env.get_string(&text.into()).ok().map(String::from));
        let _ = env.exception_clear();
        if let Some(message) = message {
            return Err(message);
        }
    }
    result.map_err(|error| error.to_string())
}

pub fn application<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JObject<'local>> {
    env.call_static_method("android/app/ActivityThread", "currentApplication", "()Landroid/app/Application;", &[])?.l()
}

/// A class of the APK (dev.tarve.*): a thread attached from native code only sees the framework's.
fn app_class<'local>(env: &mut JNIEnv<'local>, name: &str) -> jni::errors::Result<JClass<'local>> {
    let app = application(env)?;
    let loader = env.call_method(&app, "getClassLoader", "()Ljava/lang/ClassLoader;", &[])?.l()?;
    let name = env.new_string(name)?;
    let class = env.call_method(&loader, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;", &[JValue::Object(&name)])?.l()?;
    Ok(JClass::from(class))
}

/// Shows (or updates, or with `active` false ends) the notification that keeps the app running
/// in the background: Tarve's `dev.tarve.TarveKeepAlive` foreground service.
pub fn keep_alive(active: bool, title: &str, text: &str) -> Result<(), String> {
    with_env(|env| {
        let app = application(env)?;
        let class = app_class(env, "dev.tarve.TarveKeepAlive")?;
        let title = env.new_string(title)?;
        let text = env.new_string(text)?;
        env.call_static_method(
            &class,
            "update",
            "(Landroid/content/Context;ZLjava/lang/String;Ljava/lang/String;)V",
            &[JValue::Object(&app), JValue::Bool(active.into()), JValue::Object(&title), JValue::Object(&text)],
        )?;
        Ok(())
    })
}

/// Sends the app to the background, as Home does, so Back on its first screen keeps the sessions.
pub fn to_background() -> Result<(), String> {
    with_env(|env| {
        let app = application(env)?;
        let action = env.new_string("android.intent.action.MAIN")?;
        let intent = env.new_object("android/content/Intent", "(Ljava/lang/String;)V", &[JValue::Object(&action)])?;
        let category = env.new_string("android.intent.category.HOME")?;
        env.call_method(&intent, "addCategory", "(Ljava/lang/String;)Landroid/content/Intent;", &[JValue::Object(&category)])?;
        env.call_method(&intent, "setFlags", "(I)Landroid/content/Intent;", &[JValue::Int(0x1000_0000)])?;
        env.call_method(&app, "startActivity", "(Landroid/content/Intent;)V", &[JValue::Object(&intent)])?;
        Ok(())
    })
}

const KEYSTORE: &str = "AndroidKeyStore";

/// The AES key `alias` in the Android Keystore, made on first use. It never leaves the secure
/// hardware: the app can only ask it to encrypt and decrypt.
fn keystore_key<'local>(env: &mut JNIEnv<'local>, alias: &str) -> jni::errors::Result<JObject<'local>> {
    let provider = env.new_string(KEYSTORE)?;
    let store = env.call_static_method("java/security/KeyStore", "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;", &[JValue::Object(&provider)])?.l()?;
    env.call_method(&store, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V", &[JValue::Object(&JObject::null())])?;
    let name = env.new_string(alias)?;
    if env.call_method(&store, "containsAlias", "(Ljava/lang/String;)Z", &[JValue::Object(&name)])?.z()? {
        return env.call_method(&store, "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;", &[JValue::Object(&name), JValue::Object(&JObject::null())])?.l();
    }
    let algorithm = env.new_string("AES")?;
    let generator = env
        .call_static_method("javax/crypto/KeyGenerator", "getInstance", "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;", &[JValue::Object(&algorithm), JValue::Object(&provider)])?
        .l()?;
    // PURPOSE_ENCRYPT | PURPOSE_DECRYPT
    let builder = env.new_object("android/security/keystore/KeyGenParameterSpec$Builder", "(Ljava/lang/String;I)V", &[JValue::Object(&name), JValue::Int(3)])?;
    let gcm = env.new_string("GCM")?;
    let modes = env.new_object_array(1, "java/lang/String", &gcm)?;
    env.call_method(&builder, "setBlockModes", "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;", &[JValue::Object(&modes)])?;
    let none = env.new_string("NoPadding")?;
    let paddings = env.new_object_array(1, "java/lang/String", &none)?;
    env.call_method(&builder, "setEncryptionPaddings", "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;", &[JValue::Object(&paddings)])?;
    let spec = env.call_method(&builder, "build", "()Landroid/security/keystore/KeyGenParameterSpec;", &[])?.l()?;
    env.call_method(&generator, "init", "(Ljava/security/spec/AlgorithmParameterSpec;)V", &[JValue::Object(&spec)])?;
    env.call_method(&generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[])?.l()
}

fn cipher<'local>(env: &mut JNIEnv<'local>) -> jni::errors::Result<JObject<'local>> {
    let name = env.new_string("AES/GCM/NoPadding")?;
    env.call_static_method("javax/crypto/Cipher", "getInstance", "(Ljava/lang/String;)Ljavax/crypto/Cipher;", &[JValue::Object(&name)])?.l()
}

/// Encrypts `plain` with the Keystore key `alias`: the 12-byte nonce, then the ciphertext and tag.
pub fn seal(alias: &str, plain: &[u8]) -> Result<Vec<u8>, String> {
    with_env(|env| {
        let key = keystore_key(env, alias)?;
        let cipher = cipher(env)?;
        env.call_method(&cipher, "init", "(ILjava/security/Key;)V", &[JValue::Int(1), JValue::Object(&key)])?;
        let iv = JByteArray::from(env.call_method(&cipher, "getIV", "()[B", &[])?.l()?);
        let input = env.byte_array_from_slice(plain)?;
        let sealed = JByteArray::from(env.call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&input)])?.l()?);
        let mut out = env.convert_byte_array(&iv)?;
        out.extend(env.convert_byte_array(&sealed)?);
        Ok(out)
    })
}

/// Decrypts what `seal` made with the same key.
pub fn open(alias: &str, sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 12 + 16 {
        return Err("the sealed data is too short".into());
    }
    with_env(|env| {
        let key = keystore_key(env, alias)?;
        let cipher = cipher(env)?;
        let iv = env.byte_array_from_slice(&sealed[..12])?;
        let spec = env.new_object("javax/crypto/spec/GCMParameterSpec", "(I[B)V", &[JValue::Int(128), JValue::Object(&iv)])?;
        env.call_method(&cipher, "init", "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V", &[JValue::Int(2), JValue::Object(&key), JValue::Object(&spec)])?;
        let input = env.byte_array_from_slice(&sealed[12..])?;
        let plain = JByteArray::from(env.call_method(&cipher, "doFinal", "([B)[B", &[JValue::Object(&input)])?.l()?);
        env.convert_byte_array(&plain)
    })
}
