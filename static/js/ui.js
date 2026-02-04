(() => {
  const menuBtn = document.querySelector('[data-toggle="mobile-menu"]');
  const menu = document.getElementById('mobileMenu');
  const backdrop = document.getElementById('mobileMenuBackdrop');
  if (!menuBtn || !menu || !backdrop) {
    return;
  }

  const closeBtn = menu.querySelector('.mobile-close');

  function openMenu() {
    menu.hidden = false;
    backdrop.hidden = false;
    requestAnimationFrame(() => {
      menu.classList.add('open');
      backdrop.classList.add('open');
      menuBtn.setAttribute('aria-expanded', 'true');
    });
  }

  function closeMenu() {
    menu.classList.remove('open');
    backdrop.classList.remove('open');
    menuBtn.setAttribute('aria-expanded', 'false');
    setTimeout(() => {
      menu.hidden = true;
      backdrop.hidden = true;
    }, 160);
  }

  menuBtn.addEventListener('click', () => {
    const isOpen = menuBtn.getAttribute('aria-expanded') === 'true';
    if (isOpen) {
      closeMenu();
    } else {
      openMenu();
    }
  });

  backdrop.addEventListener('click', closeMenu);
  if (closeBtn) {
    closeBtn.addEventListener('click', closeMenu);
  }

  menu.addEventListener('click', (e) => {
    const target = e.target;
    if (target && target.tagName === 'A') {
      closeMenu();
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeMenu();
    }
  });
})();

(() => {
  const containers = Array.from(document.querySelectorAll('[data-notifications]'));
  if (!containers.length) {
    return;
  }

  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;
  const toastEl = document.getElementById('bfToast');
  let unreadCount = null;

  function showToast(message) {
    if (!toastEl) return;
    toastEl.textContent = message;
    toastEl.classList.add('show');
    setTimeout(() => toastEl.classList.remove('show'), 3200);
  }

  function setBadges(count) {
    containers.forEach((container) => {
      const badge = container.querySelector('[data-badge]');
      if (!badge) return;
      if (count > 0) {
        badge.textContent = count > 99 ? '99+' : String(count);
        badge.style.display = 'flex';
      } else {
        badge.style.display = 'none';
      }
    });
  }

  function getKindColor(kind) {
    switch (kind) {
      case 'success': return '#10b981';
      case 'warning': return '#f59e0b';
      case 'error': return '#ef4444';
      default: return '#3b82f6';
    }
  }

  function renderNotifications(listEl, notifications, readPrefix, viewUrl) {
    while (listEl.firstChild) {
      listEl.removeChild(listEl.firstChild);
    }

    if (!notifications || notifications.length === 0) {
      const emptyDiv = document.createElement('div');
      emptyDiv.className = 'notifications-loading';
      emptyDiv.textContent = 'No notifications';
      listEl.appendChild(emptyDiv);
      return;
    }

    notifications.forEach((n) => {
      const row = document.createElement('div');
      row.className = 'notifications-row';
      if (!n.is_read) {
        row.classList.add('unread');
      }

      const contentDiv = document.createElement('div');
      contentDiv.className = 'notifications-row-content';

      const leftDiv = document.createElement('div');
      leftDiv.className = 'notifications-row-left';

      const titleDiv = document.createElement('div');
      titleDiv.className = 'notifications-row-title';
      if (n.is_read) {
        titleDiv.classList.add('is-read');
      }
      titleDiv.textContent = n.title || '';

      const subtitleDiv = document.createElement('div');
      subtitleDiv.className = 'notifications-row-subtitle';
      const rawSubtitle = (n.body || '') || (n.actor_name ? (n.actor_name + ' posted an update.') : '');
      if (rawSubtitle) {
        const maxLen = 90;
        subtitleDiv.textContent = rawSubtitle.length > maxLen ? (rawSubtitle.slice(0, maxLen - 1) + '...') : rawSubtitle;
      }

      const timeDiv = document.createElement('div');
      timeDiv.className = 'notifications-row-time';
      if (n.created_at) {
        try {
          timeDiv.textContent = new Date(n.created_at).toLocaleString();
        } catch (e) {
          timeDiv.textContent = '';
        }
      }

      leftDiv.appendChild(titleDiv);
      if (subtitleDiv.textContent) {
        leftDiv.appendChild(subtitleDiv);
      }
      leftDiv.appendChild(timeDiv);

      const dotSpan = document.createElement('span');
      dotSpan.className = 'notifications-row-dot';
      dotSpan.style.backgroundColor = getKindColor(n.kind || 'info');

      contentDiv.appendChild(leftDiv);
      contentDiv.appendChild(dotSpan);
      row.appendChild(contentDiv);

      row.addEventListener('click', () => {
        const safeUrl = (n.url && n.url.startsWith('/')) ? n.url : null;

        if (!n.is_read && n.id && csrfToken) {
          const formData = new FormData();
          formData.append('csrf_token', csrfToken);
          fetch(`${readPrefix}/${n.id}/read`, {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
          })
          .then((response) => {
            if (response.ok) {
              row.classList.remove('unread');
              titleDiv.classList.add('is-read');
              n.is_read = true;
              unreadCount = Math.max(0, (unreadCount || 0) - 1);
              setBadges(unreadCount);
            }
          })
          .catch(() => {});
        }

        if (safeUrl) {
          window.location.href = safeUrl;
        } else {
          window.location.href = viewUrl;
        }
      });

      listEl.appendChild(row);
    });
  }

  function loadRecentNotifications(container) {
    const listEl = container.querySelector('[data-list]');
    if (!listEl) return;

    while (listEl.firstChild) {
      listEl.removeChild(listEl.firstChild);
    }
    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'notifications-loading';
    loadingDiv.textContent = 'Loading...';
    listEl.appendChild(loadingDiv);

    const recentUrl = container.dataset.recentUrl;
    const readPrefix = container.dataset.readUrlPrefix || '/notifications';
    const viewUrl = container.dataset.viewUrl || '/notifications';

    if (!recentUrl) {
      loadingDiv.textContent = 'Notifications unavailable';
      return;
    }

    fetch(recentUrl)
      .then((r) => r.json())
      .then((data) => {
        renderNotifications(listEl, data, readPrefix, viewUrl);
      })
      .catch(() => {
        const errorDiv = document.createElement('div');
        errorDiv.className = 'notifications-loading';
        errorDiv.textContent = 'Error loading notifications';
        while (listEl.firstChild) {
          listEl.removeChild(listEl.firstChild);
        }
        listEl.appendChild(errorDiv);
      });
  }

  function closeAllDropdowns(except) {
    containers.forEach((container) => {
      if (except && container === except) return;
      const dropdown = container.querySelector('[data-dropdown]');
      const toggle = container.querySelector('[data-toggle="notifications"]');
      if (dropdown) dropdown.style.display = 'none';
      if (toggle) toggle.setAttribute('aria-expanded', 'false');
    });
  }

  function updateUnreadCount() {
    const countUrl = containers[0].dataset.countUrl;
    if (!countUrl) return;
    fetch(countUrl)
      .then((r) => r.json())
      .then((data) => {
        const nextCount = data.count || 0;
        if (unreadCount !== null && nextCount > unreadCount) {
          const delta = nextCount - unreadCount;
          showToast(delta === 1 ? 'New notification' : `${delta} new notifications`);
        }
        unreadCount = nextCount;
        setBadges(nextCount);
      })
      .catch(() => {});
  }

  containers.forEach((container) => {
    const bell = container.querySelector('[data-toggle="notifications"]');
    const dropdown = container.querySelector('[data-dropdown]');
    if (!bell || !dropdown) return;

    bell.addEventListener('click', (e) => {
      e.stopPropagation();
      const isOpen = dropdown.style.display === 'block';
      closeAllDropdowns(container);
      dropdown.style.display = isOpen ? 'none' : 'block';
      bell.setAttribute('aria-expanded', isOpen ? 'false' : 'true');
      if (!isOpen) {
        updateUnreadCount();
        loadRecentNotifications(container);
      }
    });
  });

  document.addEventListener('click', (e) => {
    containers.forEach((container) => {
      const dropdown = container.querySelector('[data-dropdown]');
      const bell = container.querySelector('[data-toggle="notifications"]');
      if (!dropdown || !bell) return;
      if (!dropdown.contains(e.target) && !bell.contains(e.target)) {
        dropdown.style.display = 'none';
        bell.setAttribute('aria-expanded', 'false');
      }
    });
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeAllDropdowns(null);
    }
  });

  updateUnreadCount();
  const pollAttr = document.body?.dataset?.notifPoll;
  const pollSeconds = Math.max(10, parseInt(pollAttr || '30', 10) || 30);
  setInterval(updateUnreadCount, pollSeconds * 1000);
})();
