(() => {
  const installBtn = document.getElementById("installBtn");
  const iosTip = document.getElementById("iosInstallTip");
  const androidTip = document.getElementById("androidInstallTip");
  let deferredPrompt = null;
  let promptReady = false;

  if (!installBtn || !iosTip || !androidTip) {
    return;
  }

  const isIos = /iphone|ipad|ipod/i.test(window.navigator.userAgent);
  const isAndroid = /android/i.test(window.navigator.userAgent);
  const isStandalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone;

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    promptReady = true;
    installBtn.style.display = "inline-flex";
    androidTip.style.display = "none";
  });

  installBtn.addEventListener("click", async () => {
    if (!deferredPrompt) {
      return;
    }
    deferredPrompt.prompt();
    try {
      await deferredPrompt.userChoice;
    } catch (err) {
      // Ignore; user dismissed.
    }
    deferredPrompt = null;
    installBtn.style.display = "none";
  });

  if (isIos && !isStandalone) {
    iosTip.style.display = "block";
  }

  window.addEventListener("load", () => {
    if (isAndroid && !isStandalone && !promptReady) {
      setTimeout(() => {
        if (!promptReady) {
          androidTip.style.display = "block";
        }
      }, 1200);
    }
  });

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/sw.js");
  }
})();
