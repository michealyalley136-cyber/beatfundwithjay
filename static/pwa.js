(() => {
  const installBtn = document.getElementById("installBtn");
  const iosTip = document.getElementById("iosInstallTip");
  let deferredPrompt = null;

  if (!installBtn || !iosTip) {
    return;
  }

  const isIos = /iphone|ipad|ipod/i.test(window.navigator.userAgent);
  const isStandalone = window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone;

  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredPrompt = e;
    installBtn.style.display = "inline-flex";
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

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("/static/sw.js");
  }
})();
