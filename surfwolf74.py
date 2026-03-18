# surfwolf74.py
# Surfwolf74 - PyQt6 Web Browser
# Autor: Rob de Roy
import sys
import os
import json
import tempfile
import webbrowser
from PyQt6.QtCore import Qt, QUrl, QPoint, QStringListModel, QSize, QObject, QTimer, QMimeData
from PyQt6.QtGui import QIcon, QFont, QAction, QDrag
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QToolBar, QLineEdit, QStatusBar,
    QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QTabWidget, QMenu,
    QInputDialog, QMessageBox, QCompleter, QSizePolicy, QToolButton,
    QLabel, QDialog, QListWidget, QListWidgetItem
)
from PyQt6.QtWebEngineCore import (
    QWebEngineProfile,
    QWebEnginePage,
    QWebEngineSettings,
    QWebEngineUrlScheme,
    QWebEngineUrlRequestInterceptor,
    QWebEngineUrlRequestInfo,
    QWebEngineScript
)
from PyQt6.QtWebEngineWidgets import QWebEngineView



# -------- Pfade --------
def get_base_path():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

APP_PATH = get_base_path()
ICON_PATH = os.path.join(APP_PATH, "icon.ico")
START_IMAGE_PATH = os.path.join(APP_PATH, "surfwolf74.png")
BOOKMARKS_FILE = os.path.join(APP_PATH, "bookmarks.json")
CONFIG_FILE = os.path.join(APP_PATH, "config.json")
BLOCKED_SITES_FILE = os.path.join(APP_PATH, "blocked_sites.json")


# -------- Blocked Sites Management --------
def load_blocked_sites():
    try:
        with open(BLOCKED_SITES_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (FileNotFoundError, json.JSONDecodeError):
        return set()

def save_blocked_sites(sites):
    try:
        with open(BLOCKED_SITES_FILE, "w", encoding="utf-8") as f:
            json.dump(list(sites), f, indent=2, ensure_ascii=False)
    except Exception:
        pass

blocked_sites = load_blocked_sites()


# -------- view-source: Schema registrieren (MUSS VOR QApplication!)
def register_view_source():
    scheme = QWebEngineUrlScheme(b"view-source")
    scheme.setFlags(
        QWebEngineUrlScheme.Flag.CorsEnabled |
        QWebEngineUrlScheme.Flag.LocalAccessAllowed |
        QWebEngineUrlScheme.Flag.ContentSecurityPolicyIgnored
    )
    QWebEngineUrlScheme.registerScheme(scheme)


# -------- Hilfsfunktion für Website-Sperrung --------
def is_site_blocked(host):
    """Prüft ob eine Domain gesperrt ist"""
    host = host.lower()
    for blocked_domain in blocked_sites:
        if blocked_domain.lower() in host:
            return True
    return False


# -------- CSP Interceptor (BROWSERAUDIT-OPTIMIERT) --------
class DNTInterceptor(QWebEngineUrlRequestInterceptor):
    # Klassen-Konstanten: einmal erstellt, bei jedem Request wiederverwendet
    BYPASS_DOMAINS = frozenset(["wolframgruppe.de", "investing.com", "browseraudit.com"])
    BLOCK_PATTERNS = frozenset([
        'doubleclick.net', 'googlesyndication.com', 'googletagmanager.com',
        'google-analytics.com', 'adservice.google.com', 'facebook.com/tr',
        'connect.facebook.net', 'ads.yahoo.com', 'ads.pubmatic.com',
        'scorecardresearch.com', 'mathtag.com', 'adnxs.com', 'criteo.com',
        'taboola.com', 'outbrain.com', 'bing.com/ads', 'twitter.com/i/ads',
        'amazon-adsystem.com', 'quantserve.com', 'bluekai.com',
        'rubiconproject.com', 'yieldmo.com', 'moatads.com', 'adform.net',
        'openx.net', 'casalemedia.com', 'media.net', 'smartadserver.com',
        'serving-sys.com', 'siteimproveanalytics.com', 'googletagservices.com',
        'googletag.com', 'adroll.com', 'adblade.com', 'adzerk.net',
        'advertising.com', 'contextweb.com', 'exponential.com',
        'fastclick.net', 'media6degrees.com', 'quantcast.com',
        'revcontent.com', 'adcolony.com', 'adap.tv', 'adtechus.com'
    ])

    # Vorberechnete Header-Bytes für browseraudit.com
    _PERMISSIONS_BROWSERAUDIT = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), midi=(), "
        "serial=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=(), "
        "ambient-light-sensor=(), autoplay=(self), encrypted-media=(self), "
        "fullscreen=(self), picture-in-picture=(self), display-capture=(), "
        "web-share=(self), screen-wake-lock=(), publickey-credentials-get=(self)"
    ).encode('utf-8')
    _PERMISSIONS_STRICT = (
        "geolocation=(), microphone=(), camera=(), payment=(), usb=(), midi=(), "
        "serial=(), bluetooth=(), magnetometer=(), gyroscope=(), accelerometer=(), "
        "ambient-light-sensor=(), autoplay=(), encrypted-media=(), fullscreen=(), "
        "picture-in-picture=(), display-capture=(), web-share=(), "
        "screen-wake-lock=(), publickey-credentials-get=()"
    ).encode('utf-8')
    _CSP_BROWSERAUDIT = (
        "default-src 'self' https://browseraudit.com https://test.browseraudit.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://browseraudit.com https://test.browseraudit.com; "
        "style-src 'self' 'unsafe-inline' https://browseraudit.com https://test.browseraudit.com; "
        "img-src 'self' data: https: https://browseraudit.com https://test.browseraudit.com; "
        "connect-src 'self' https: wss: ws: https://browseraudit.com https://test.browseraudit.com wss://browseraudit.com; "
        "font-src 'self' https: https://browseraudit.com https://test.browseraudit.com; "
        "media-src 'self' https://browseraudit.com https://test.browseraudit.com; "
        "object-src 'none'; base-uri 'self'; "
        "form-action 'self' https://browseraudit.com https://test.browseraudit.com; "
        "frame-ancestors 'self' https://browseraudit.com https://test.browseraudit.com; "
        "worker-src 'self' https://browseraudit.com https://test.browseraudit.com; "
        "manifest-src 'self' https://browseraudit.com https://test.browseraudit.com; "
        "upgrade-insecure-requests"
    ).encode('utf-8')
    _CSP_STRICT = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https:; "
        "font-src 'self' https:; "
        "media-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests; "
        "block-all-mixed-content"
    ).encode('utf-8')

    def __init__(self, mode="normal"):
        super().__init__()
        self.mode = mode

    def interceptRequest(self, info: QWebEngineUrlRequestInfo):
        try:
            host = info.requestUrl().host().lower()

            # Website-Sperrung prüfen
            if is_site_blocked(host):
                info.block(True)
                return

            # Im Normal-Modus nur Sperrung prüfen, sonst nichts
            if self.mode == "normal":
                return

            # Bypass für bestimmte Domains im Strict-Modus
            if any(domain in host for domain in self.BYPASS_DOMAINS):
                self._set_security_headers(info, host)
                return

            # Ad-Blocker im Strict-Modus
            url = info.requestUrl().toString()
            if any(pattern in url for pattern in self.BLOCK_PATTERNS):
                info.block(True)
                return

            self._set_security_headers(info, host)

        except Exception as e:
            print(f"Interceptor Fehler: {e}")

    def _set_security_headers(self, info, host):
        """Setzt Sicherheitsheader - host wird einmal übergeben statt 6x neu berechnet"""
        is_audit = "browseraudit.com" in host

        # Privacy Headers
        info.setHttpHeader(b"DNT", b"1")
        info.setHttpHeader(b"Sec-GPC", b"1")
        info.setHttpHeader(b"X-Content-Type-Options", b"nosniff")
        info.setHttpHeader(b"X-XSS-Protection", b"1; mode=block")
        info.setHttpHeader(b"Expect-CT", b"max-age=86400, enforce")
        info.setHttpHeader(b"X-Permitted-Cross-Domain-Policies", b"none")

        if is_audit:
            info.setHttpHeader(b"X-Frame-Options", b"ALLOWALL")
            info.setHttpHeader(b"Referrer-Policy", b"origin")
            info.setHttpHeader(b"Permissions-Policy", self._PERMISSIONS_BROWSERAUDIT)
            info.setHttpHeader(b"Cross-Origin-Embedder-Policy", b"unsafe-none")
            info.setHttpHeader(b"Cross-Origin-Opener-Policy", b"unsafe-none")
            info.setHttpHeader(b"Cross-Origin-Resource-Policy", b"cross-origin")
            info.setHttpHeader(b"Access-Control-Expose-Headers", b"Content-Length, Content-Type, Date, Connection, Cache-Control, Pragma, Expires")
            info.setHttpHeader(b"Content-Security-Policy", self._CSP_BROWSERAUDIT)
            info.setHttpHeader(b"Strict-Transport-Security", b"max-age=31536000; includeSubDomains")
            info.setHttpHeader(b"Cache-Control", b"public, max-age=3600")
            info.setHttpHeader(b"Pragma", b"cache")
        else:
            info.setHttpHeader(b"X-Frame-Options", b"SAMEORIGIN")
            info.setHttpHeader(b"Referrer-Policy", b"no-referrer")
            info.setHttpHeader(b"Permissions-Policy", self._PERMISSIONS_STRICT)
            info.setHttpHeader(b"Cross-Origin-Embedder-Policy", b"require-corp")
            info.setHttpHeader(b"Cross-Origin-Opener-Policy", b"same-origin")
            info.setHttpHeader(b"Cross-Origin-Resource-Policy", b"same-origin")
            info.setHttpHeader(b"Content-Security-Policy", self._CSP_STRICT)
            info.setHttpHeader(b"Strict-Transport-Security", b"max-age=31536000; includeSubDomains; preload")
            info.setHttpHeader(b"Cache-Control", b"no-cache, no-store, must-revalidate")
            info.setHttpHeader(b"Pragma", b"no-cache")
            info.setHttpHeader(b"Expires", b"0")


# -------- Custom WebEnginePage --------
class CustomWebEnginePage(QWebEnginePage):
    def __init__(self, profile, browser_window):
        super().__init__(profile)
        self.browser_window = browser_window
        # Link-Hover-Event richtig verbinden
        self.linkHovered.connect(self.on_link_hovered)

    def on_link_hovered(self, url):
        """Zeigt Link-URL in der Statusleiste beim Hover"""
        if url:
            self.browser_window.statusBar().showMessage(f"🔗 {url}", 0)
        else:
            self.browser_window.statusBar().clearMessage()

    def createWindow(self, window_type):
        # Nur neue Tabs erstellen wenn bereits ein Tab existiert (Browser gestartet)
        if self.browser_window.tabs.count() > 0:
            if window_type == QWebEnginePage.WebWindowType.WebBrowserTab:
                new_tab = self.browser_window.add_new_tab()
                return new_tab.page()
            elif window_type == QWebEnginePage.WebWindowType.WebBrowserWindow:
                new_tab = self.browser_window.add_new_tab()  
                return new_tab.page()
        # Während der Initialisierung oder wenn keine Tabs vorhanden: Standard-Verhalten
        return super().createWindow(window_type)

    def acceptNavigationRequest(self, url, navigation_type, is_main_frame):
        """Kontrolliert welche Navigationen erlaubt werden"""
        url_string = url.toString()
        host = url.host().lower()
        
        # Debugging
        print(f"Navigation Request: {url_string} (Type: {navigation_type}, MainFrame: {is_main_frame})")
        
        # view-source URLs immer erlauben
        if url.scheme() == "view-source":
            return True
        
        # about: URLs immer erlauben (about:blank, etc.)
        if url.scheme() == "about":
            return True
        
        # data: URLs immer erlauben (Base64-eingebettete Inhalte)
        if url.scheme() == "data":
            return True
        
        # WEBSITE-SPERRUNG: Gesperrte Domains SOFORT blockieren
        if url.host():
            host = url.host().lower()
            if is_site_blocked(host):
                    print(f"BLOCKIERT: Navigation zu gesperrter Website {host} verhindert")
                    # Statusmeldung in der Hauptanwendung anzeigen
                    if hasattr(self.browser_window, 'statusBar'):
                        self.browser_window.statusBar().showMessage(f"🚫 Zugriff verweigert: {host} ist gesperrt", 5000)
                    return False  # Navigation komplett verhindern
            
        # Alle anderen Navigationen erlauben
        return True

    def javaScriptConsoleMessage(self, level, message, lineNumber, sourceID):
        """JavaScript Konsole Nachrichten anzeigen"""
        print(f"JS Console: {message} (Line: {lineNumber})")
        super().javaScriptConsoleMessage(level, message, lineNumber, sourceID)


# -------- BrowserTab (KORRIGIERT) --------
class BrowserTab(QWebEngineView):
    def __init__(self, parent, browser_window, profile, js_enabled=True):
        super().__init__(parent)
        self.browser_window = browser_window
        self.profile = profile

        # Page ZUERST erstellen
        page = CustomWebEnginePage(self.profile, browser_window)
        self.setPage(page)

        # Settings über die Page, nicht das Profil
        settings = page.settings()
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, js_enabled)
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanOpenWindows, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptCanAccessClipboard, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalStorageEnabled, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowRunningInsecureContent, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.AllowWindowActivationFromJavaScript, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.ShowScrollBars, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.PlaybackRequiresUserGesture, True)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.WebRTCPublicInterfacesOnly, True)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.DnsPrefetchEnabled, False)  # Privacy
        settings.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.FullScreenSupportEnabled, False)  # Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.PdfViewerEnabled, False)  # Sicherheit
        # Navigation kontrollieren für Sicherheit
        settings.setAttribute(QWebEngineSettings.WebAttribute.FocusOnNavigationEnabled, True)
        
        # Zusätzliche Sicherheitsattribute für browseraudit.com Tests
        settings.setAttribute(QWebEngineSettings.WebAttribute.AutoLoadImages, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.SpatialNavigationEnabled, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.LinksIncludedInFocusChain, False)
        settings.setAttribute(QWebEngineSettings.WebAttribute.ErrorPageEnabled, True)
        settings.setAttribute(QWebEngineSettings.WebAttribute.Accelerated2dCanvasEnabled, False)  # Fingerprinting-Schutz
        
        # Font-Einstellungen für native Windows-Schriften (Anti-Fingerprinting)
        if browser_window.security_mode == "strict":
            # Im Strict-Modus einheitliche Fonts zur Fingerprinting-Prevention
            settings.setFontFamily(QWebEngineSettings.FontFamily.StandardFont, "Arial")
            settings.setFontFamily(QWebEngineSettings.FontFamily.SerifFont, "Times New Roman")
            settings.setFontFamily(QWebEngineSettings.FontFamily.SansSerifFont, "Arial")
            settings.setFontFamily(QWebEngineSettings.FontFamily.FixedFont, "Courier New")
            settings.setFontSize(QWebEngineSettings.FontSize.DefaultFontSize, 16)
            settings.setFontSize(QWebEngineSettings.FontSize.DefaultFixedFontSize, 13)
            settings.setFontSize(QWebEngineSettings.FontSize.MinimumFontSize, 12)
        else:
            # Im Normal-Modus native Schriften
            settings.setFontFamily(QWebEngineSettings.FontFamily.StandardFont, "Segoe UI")
            settings.setFontFamily(QWebEngineSettings.FontFamily.SerifFont, "Times New Roman")
            settings.setFontFamily(QWebEngineSettings.FontFamily.SansSerifFont, "Segoe UI")
            settings.setFontFamily(QWebEngineSettings.FontFamily.FixedFont, "Consolas")
            settings.setFontSize(QWebEngineSettings.FontSize.DefaultFontSize, 16)
            settings.setFontSize(QWebEngineSettings.FontSize.DefaultFixedFontSize, 14)

        # BARRIEREFREIHEIT - Nur essentielle Accessibility-Einstellungen ohne CSS-Injection
        self.setup_accessibility_features(settings)


        
    def setup_accessibility_features(self, settings):
        """Konfiguriert nur grundlegende Barrierefreiheits-Features ohne aggressive CSS-Änderungen"""
        # Höhere Mindestschriftgröße für bessere Lesbarkeit
        settings.setFontSize(QWebEngineSettings.FontSize.MinimumFontSize, 14)
        settings.setFontSize(QWebEngineSettings.FontSize.MinimumLogicalFontSize, 14)
        
        # Spatial Navigation für Keyboard-Navigation aktivieren
        settings.setAttribute(QWebEngineSettings.WebAttribute.SpatialNavigationEnabled, True)
        
        # Links in Tab-Navigation einbeziehen
        settings.setAttribute(QWebEngineSettings.WebAttribute.LinksIncludedInFocusChain, True)
        
        # Focus auf Navigation aktivieren
        settings.setAttribute(QWebEngineSettings.WebAttribute.FocusOnNavigationEnabled, True)
        
        # KEINE CSS-Injection mehr - nur Browser-interne Accessibility-Features
        
        # Anti-Fingerprinting-Script im Strict-Modus injizieren
        if self.browser_window.security_mode == "strict":
            self.inject_anti_fingerprinting_script()

        # Direkt DuckDuckGo laden statt Startseite
        self.setUrl(QUrl("https://duckduckgo.com"))

    def inject_anti_fingerprinting_script(self):
        """Injiziert JavaScript um Browser-Fingerprinting zu verhindern"""
        anti_fingerprint_script = """
        (function() {
            console.log('SurfWolf74: Anti-Fingerprinting Script aktiviert');
            
            // Screen Resolution spoofing
            Object.defineProperty(screen, 'width', { value: 1920, writable: false });
            Object.defineProperty(screen, 'height', { value: 1080, writable: false });
            Object.defineProperty(screen, 'availWidth', { value: 1920, writable: false });
            Object.defineProperty(screen, 'availHeight', { value: 1040, writable: false });
            Object.defineProperty(screen, 'colorDepth', { value: 24, writable: false });
            Object.defineProperty(screen, 'pixelDepth', { value: 24, writable: false });
            
            // Timezone spoofing
            Date.prototype.getTimezoneOffset = function() { return 0; };
            
            // Language spoofing
            Object.defineProperty(navigator, 'language', { value: 'en-US', writable: false });
            Object.defineProperty(navigator, 'languages', { value: ['en-US', 'en'], writable: false });
            
            // Platform spoofing
            Object.defineProperty(navigator, 'platform', { value: 'Win32', writable: false });
            
            // Hardware concurrency spoofing
            Object.defineProperty(navigator, 'hardwareConcurrency', { value: 4, writable: false });
            
            // Device memory spoofing
            if ('deviceMemory' in navigator) {
                Object.defineProperty(navigator, 'deviceMemory', { value: 8, writable: false });
            }
            
            // WebGL fingerprinting protection
            const getParameter = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(parameter) {
                if (parameter === 37445) { // UNMASKED_VENDOR_WEBGL
                    return 'Intel Inc.';
                }
                if (parameter === 37446) { // UNMASKED_RENDERER_WEBGL
                    return 'Intel Iris OpenGL Engine';
                }
                return getParameter.call(this, parameter);
            };
            
            // Canvas fingerprinting protection
            const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
            HTMLCanvasElement.prototype.toDataURL = function() {
                const context = this.getContext('2d');
                if (context) {
                    // Noise hinzufügen um Canvas-Fingerprinting zu verhindern
                    const imageData = context.getImageData(0, 0, this.width, this.height);
                    for (let i = 0; i < imageData.data.length; i += 4) {
                        imageData.data[i] = imageData.data[i] + Math.floor(Math.random() * 2);
                    }
                    context.putImageData(imageData, 0, 0);
                }
                return originalToDataURL.apply(this, arguments);
            };
            
            // AudioContext fingerprinting protection
            if (window.AudioContext || window.webkitAudioContext) {
                const AudioContextProto = (window.AudioContext || window.webkitAudioContext).prototype;
                const originalCreateAnalyser = AudioContextProto.createAnalyser;
                AudioContextProto.createAnalyser = function() {
                    const analyser = originalCreateAnalyser.call(this);
                    const originalGetFloatFrequencyData = analyser.getFloatFrequencyData;
                    analyser.getFloatFrequencyData = function(array) {
                        originalGetFloatFrequencyData.call(this, array);
                        // Noise hinzufügen
                        for (let i = 0; i < array.length; i++) {
                            array[i] = array[i] + Math.random() * 0.0001;
                        }
                    };
                    return analyser;
                };
            }
            
            // Battery API blockieren
            if ('getBattery' in navigator) {
                navigator.getBattery = undefined;
            }
            
            // GamePad API blockieren
            if ('getGamepads' in navigator) {
                navigator.getGamepads = function() { return []; };
            }
            
            // Media Devices API blockieren
            if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
                navigator.mediaDevices.enumerateDevices = function() {
                    return Promise.resolve([]);
                };
            }
            
            console.log('SurfWolf74: Browser-Fingerprinting-Schutz aktiviert');
        })();
        """
        
        def anti_fingerprint_injected(result):
            print(f"Anti-Fingerprinting Script injiziert: {result}")
            
        self.page().runJavaScript(anti_fingerprint_script, anti_fingerprint_injected)

    def contextMenuEvent(self, event):
        """Custom Context Menu mit funktionierenden Actions"""
        menu = QMenu(self)
        
        # Standard Browser-Actions
        if self.history().canGoBack():
            back_action = menu.addAction("← Zurück")
            back_action.triggered.connect(self.back)
            
        if self.history().canGoForward():
            forward_action = menu.addAction("→ Vorwärts")  
            forward_action.triggered.connect(self.forward)
            
        reload_action = menu.addAction("↻ Neu laden")
        reload_action.triggered.connect(self.reload)
        
        menu.addSeparator()
        
        # JavaScript verwenden um Link-Informationen zu erhalten
        self.get_link_under_cursor(event.pos(), menu, event.globalPos())

    def get_link_under_cursor(self, local_pos, menu, global_pos):
        """Ermittelt Link unter Cursor via JavaScript"""
        js_code = f"""
        (function() {{
            var element = document.elementFromPoint({local_pos.x()}, {local_pos.y()});
            var link = null;
            var selectedText = window.getSelection().toString();
            
            // Nach Link-Element suchen (auch in Parent-Elementen)
            var current = element;
            while (current && current !== document) {{
                if (current.tagName === 'A' && current.href) {{
                    link = current.href;
                    break;
                }}
                current = current.parentElement;
            }}
            
            return {{
                hasLink: !!link,
                linkUrl: link || '',
                selectedText: selectedText,
                tagName: element ? element.tagName : '',
                hasImage: element && element.tagName === 'IMG'
            }};
        }})();
        """
        
        def handle_js_result(result):
            self.build_context_menu_with_data(menu, result, global_pos)
            
        self.page().runJavaScript(js_code, handle_js_result)

    def build_context_menu_with_data(self, menu, data, global_pos):
        """Baut das Context Menu mit den JavaScript-Daten auf"""
        
        # Link-spezifische Actions
        if data and data.get('hasLink') and data.get('linkUrl'):
            link_url = data['linkUrl']
            
            open_link_action = menu.addAction("🔗 Link öffnen")
            open_link_action.triggered.connect(lambda: self.load(QUrl(link_url)))
            
            new_tab_action = menu.addAction("🔗 Link in neuem Tab öffnen")
            new_tab_action.triggered.connect(lambda: self.browser_window.add_new_tab(link_url))
            
            copy_link_action = menu.addAction("📋 Link kopieren")
            copy_link_action.triggered.connect(lambda: QApplication.clipboard().setText(link_url))
            
            menu.addSeparator()
        
        # Text-spezifische Actions
        if data and data.get('selectedText'):
            selected_text = data['selectedText'].strip()
            if selected_text:
                copy_text_action = menu.addAction("📋 Text kopieren")
                copy_text_action.triggered.connect(lambda: QApplication.clipboard().setText(selected_text))
                
                search_action = menu.addAction("🔍 Text suchen")
                search_action.triggered.connect(lambda: self.search_text(selected_text))
                
                menu.addSeparator()
        
        # Website-Sperr-Funktionen
        current_url = self.page().url()
        if current_url and current_url.host():
            domain = current_url.host()
            tab = self
            
            if domain in blocked_sites:
                unblock_action = menu.addAction(f"🔓 Website entsperren: {domain}")
                unblock_action.triggered.connect(lambda: self.browser_window.unblock_site(domain, tab))
            else:
                block_action = menu.addAction(f"🚫 Website sperren: {domain}")
                block_action.triggered.connect(lambda: self.browser_window.block_site(domain, tab))
            
            menu.addSeparator()
        
        # Quelltext anzeigen
        current_url_str = self.page().url().toString()
        if current_url_str and not current_url_str.startswith("view-source:"):
            view_source_action = menu.addAction("📄 Quelltext anzeigen")
            view_source_action.triggered.connect(lambda: self.show_page_source())
        
        # Neuer leerer Tab
        menu.addSeparator()
        new_empty_tab_action = menu.addAction("➕ Neuer Tab")
        new_empty_tab_action.triggered.connect(lambda: self.browser_window.add_new_tab())
        
        # Menu anzeigen
        menu.exec(global_pos)

    def search_text(self, text):
        """Sucht den ausgewählten Text"""
        search_url = f"https://duckduckgo.com/?q={text}"
        self.browser_window.add_new_tab(search_url)

    def show_dev_tools(self):
        """Zeigt die Entwicklertools"""
        self.browser_window.toggle_dev_tools()

    def show_page_source(self):
        """Zeigt den Quelltext der aktuellen Seite"""
        current_url = self.page().url().toString()
        if current_url:
            source_url = f"view-source:{current_url}"
            self.browser_window.add_new_tab(source_url)


# -------- Hauptfenster (KORRIGIERT) --------
# Einfache draggable Bookmark-Klasse mit visuellem Feedback
class DraggableBookmarkButton(QToolButton):
    def __init__(self, name, url, browser_window):
        super().__init__()
        self.bookmark_name = name
        self.bookmark_url = url
        self.browser_window = browser_window
        self.original_text = name
        self.setText(name)
        self.setToolTip(url)
        self.setProperty("bookmark_name", name)
        self.setAcceptDrops(True)
        self.is_dragging = False
        
    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.drag_start_position = event.position().toPoint()
            # Visuelles Feedback: Button mit X markieren
            self.setText(f"✕ {self.original_text}")
            self.setStyleSheet(self.browser_window.drag_colors['pressed'])
        elif event.button() == Qt.MouseButton.RightButton:
            # Rechtsklick für Kontextmenü
            self.browser_window.show_bookmark_context_menu(self.bookmark_name, event.pos(), self)
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not (event.buttons() & Qt.MouseButton.LeftButton):
            return
        if (event.position().toPoint() - self.drag_start_position).manhattanLength() < QApplication.startDragDistance():
            return
        
        self.is_dragging = True
        # Während des Drags: Intensiveres visuelles Feedback
        self.setText(f"↔ {self.original_text}")
        self.setStyleSheet(self.browser_window.drag_colors['dragging'])
            
        drag = QDrag(self)
        mimeData = QMimeData()
        mimeData.setText(f"bookmark:{self.bookmark_name}")
        drag.setMimeData(mimeData)
        
        # Nach dem Drag: Zurück zum normalen Aussehen
        result = drag.exec(Qt.DropAction.MoveAction)
        self.reset_appearance()
    
    def dragEnterEvent(self, event):
        if event.mimeData().hasText() and event.mimeData().text().startswith("bookmark:"):
            # Drop-Zone Feedback
            self.setStyleSheet(self.browser_window.drag_colors['drop_zone'])
            event.acceptProposedAction()
    
    def dragLeaveEvent(self, event):
        # Zurück zum normalen Aussehen wenn Drag verlässt
        if not self.is_dragging:
            self.reset_appearance()
    
    def dropEvent(self, event):
        if event.mimeData().hasText():
            drag_name = event.mimeData().text().split(":")[1]
            if drag_name != self.bookmark_name:
                self.browser_window.reorder_bookmarks(drag_name, self.bookmark_name)
            event.acceptProposedAction()
        self.reset_appearance()
            
    def mouseReleaseEvent(self, event):
        # Button zurücksetzen wenn Maus losgelassen wird
        self.reset_appearance()
        
        if event.button() == Qt.MouseButton.LeftButton and not self.is_dragging:
            # Navigation nur wenn nicht gedraggt wurde
            current_tab = self.browser_window.tabs.currentWidget()
            if current_tab:
                current_tab.setUrl(QUrl(self.bookmark_url))
        
        self.is_dragging = False
        super().mouseReleaseEvent(event)
    
    def reset_appearance(self):
        """Setzt das Aussehen des Buttons zurück"""
        self.setText(self.original_text)
        self.setStyleSheet("")

class BrowserWindow(QMainWindow):
    def load_bookmarks(self):
        try:
            with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Verschiedene Bookmark-Formate handhaben
            if isinstance(data, dict) and 'bookmarks' in data:
                bookmarks = data
            elif isinstance(data, list):
                # Altes Format: Liste zu Dict konvertieren
                bookmarks = {'bookmarks': {}}
                for item in data:
                    if isinstance(item, dict) and 'name' in item and 'url' in item:
                        bookmarks['bookmarks'][item['name']] = item['url']
                    elif isinstance(item, str):
                        bookmarks['bookmarks'][item] = 'https://www.google.com'
            else:
                raise Exception("Unbekanntes Format")
                
        except (FileNotFoundError, json.JSONDecodeError, Exception):
            bookmarks = {
                'bookmarks': {
                    'Google': 'https://www.google.com',
                    'YouTube': 'https://www.youtube.com',
                    'GitHub': 'https://github.com'
                }
            }
            try:
                with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(bookmarks, f, indent=4, ensure_ascii=False)
            except Exception:
                pass
        # Entferne alle Favoriten-Buttons aus der Bookmarks-Toolbar
        bookmark_actions = []
        if hasattr(self, 'bookmarks_toolbar'):  # Neue Zwei-Toolbar-Struktur
            toolbar = self.bookmarks_toolbar
        else:  # Fallback für alte Struktur
            toolbar = getattr(self, 'main_toolbar', None)
            
        if toolbar:
            for action in list(toolbar.actions()):
                widget = toolbar.widgetForAction(action)
                if isinstance(widget, QToolButton):
                    bookmark_name = widget.property("bookmark_name")
                    if bookmark_name:
                        bookmark_actions.append(action)
            
            for action in bookmark_actions:
                toolbar.removeAction(action)
        
        # Favoriten als DraggableBookmarkButton
        # Sammle zuerst alle zu erstellenden Favoriten
        bookmark_buttons = []
        for name, url in bookmarks.get('bookmarks', {}).items():
            btn = DraggableBookmarkButton(name, url, self)
            bookmark_buttons.append(btn)
        
        # Füge alle Favoriten in die Bookmarks-Toolbar ein
        if hasattr(self, 'bookmarks_toolbar'):  # Neue Zwei-Toolbar-Struktur
            # Alle Bookmarks in der separaten Bookmarks-Toolbar hinzufügen
            for btn in bookmark_buttons:
                self.bookmarks_toolbar.addWidget(btn)
        else:  # Fallback für alte Ein-Toolbar-Struktur
            for btn in bookmark_buttons:
                self.main_toolbar.addWidget(btn)

    def reorder_bookmarks(self, drag_name, target_name):
        """Ändert die Reihenfolge der Bookmarks"""
        try:
            with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            # Listen-Format handhaben
            if isinstance(data, list):
                # Finde die Bookmark-Objekte
                drag_bookmark = None
                target_index = None
                
                for i, item in enumerate(data):
                    if isinstance(item, dict):
                        if item.get('name') == drag_name:
                            drag_bookmark = item
                        if item.get('name') == target_name:
                            target_index = i
                
                if drag_bookmark and target_index is not None:
                    # Entferne das verschobene Bookmark
                    data.remove(drag_bookmark)
                    # Füge es an der neuen Position ein
                    data.insert(target_index, drag_bookmark)
                    
                    # Speichern
                    with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                        json.dump(data, f, indent=2, ensure_ascii=False)
                    
                    # UI aktualisieren
                    self.load_bookmarks()
                    
            # Dict-Format handhaben
            elif isinstance(data, dict) and 'bookmarks' in data:
                bookmark_dict = data['bookmarks']
                
                if drag_name in bookmark_dict and target_name in bookmark_dict:
                    # Aktuelle Reihenfolge der Namen
                    bookmark_names = list(bookmark_dict.keys())
                    
                    # Finde Indizes
                    drag_index = bookmark_names.index(drag_name)
                    target_index = bookmark_names.index(target_name)
                    
                    # Verschiebe das Element
                    bookmark_names.insert(target_index, bookmark_names.pop(drag_index))
                    
                    # Neue Reihenfolge erstellen
                    new_bookmarks = {}
                    for name in bookmark_names:
                        new_bookmarks[name] = bookmark_dict[name]
                    
                    # Speichern im korrekten Format
                    bookmarks_data = {'bookmarks': new_bookmarks}
                    with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                        json.dump(bookmarks_data, f, indent=4, ensure_ascii=False)
                    
                    # UI aktualisieren
                    self.load_bookmarks()
                
        except Exception as e:
            print(f"Fehler beim Neuordnen der Bookmarks: {e}")

    def show_bookmark_context_menu(self, bookmark_name, pos, btn):
        menu = QMenu(self)
        rename_action = QAction("Umbenennen", self)
        rename_action.triggered.connect(lambda: self.rename_bookmark(bookmark_name))
        menu.addAction(rename_action)
        delete_action = QAction("Löschen", self)
        delete_action.triggered.connect(lambda: self.delete_bookmark(bookmark_name))
        menu.addAction(delete_action)
        menu.exec(btn.mapToGlobal(pos))

    def add_bookmark(self):
        """Aktuelle Seite zu Lesezeichen hinzufügen"""
        current_tab = self.tabs.currentWidget()
        if not current_tab:
            return
        url = current_tab.url().toString()
        title = current_tab.page().title() or "Neue Seite"
        name, ok = QInputDialog.getText(self, "Lesezeichen hinzufügen", f"Name für das Lesezeichen:\n\nURL: {url}", QLineEdit.EchoMode.Normal, title)
        if ok and name:
            self._add_bookmark_to(name, url)

    def _add_bookmark_to(self, name, url):
        """Lesezeichen zu Datei hinzufügen"""
        try:
            with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            data = []
            
        # Listen-Format handhaben
        if isinstance(data, list):
            # Prüfen ob Bookmark bereits existiert
            for item in data:
                if isinstance(item, dict) and item.get('name') == name:
                    QMessageBox.warning(self, "Fehler", f"Lesezeichen '{name}' existiert bereits.")
                    return
            # Neues Bookmark hinzufügen
            data.append({"name": name, "url": url})
        else:
            # Dict-Format (falls noch vorhanden)
            if "bookmarks" not in data:
                data["bookmarks"] = {}
            data["bookmarks"][name] = url
            
        try:
            with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            self.load_bookmarks()
            QMessageBox.information(self, "Erfolg", f"Lesezeichen '{name}' wurde hinzugefügt.")
        except Exception as e:
            QMessageBox.warning(self, "Fehler", f"Fehler beim Speichern: {e}")

    def rename_bookmark(self, bookmark_name):
        new_name, ok = QInputDialog.getText(self, "Lesezeichen umbenennen", f"Neuer Name für Lesezeichen '{bookmark_name}':")
        if ok and new_name and new_name != bookmark_name:
            try:
                with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Listen-Format handhaben
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and item.get('name') == bookmark_name:
                            item['name'] = new_name
                            break
                else:
                    # Dict-Format
                    if bookmark_name in data["bookmarks"]:
                        data["bookmarks"][new_name] = data["bookmarks"].pop(bookmark_name)
                        
                with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                self.load_bookmarks()
            except Exception as e:
                QMessageBox.warning(self, "Fehler", f"Fehler beim Umbenennen: {e}")

    def delete_bookmark(self, bookmark_name):
        """Lesezeichen löschen"""
        reply = QMessageBox.question(self, "Lesezeichen löschen", f"Lesezeichen '{bookmark_name}' wirklich löschen?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            try:
                with open(BOOKMARKS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    
                # Listen-Format handhaben
                if isinstance(data, list):
                    for i, item in enumerate(data):
                        if isinstance(item, dict) and item.get('name') == bookmark_name:
                            data.pop(i)
                            break
                else:
                    # Dict-Format
                    data["bookmarks"].pop(bookmark_name, None)
                    
                with open(BOOKMARKS_FILE, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                self.load_bookmarks()
            except Exception as e:
                QMessageBox.warning(self, "Fehler", f"Fehler beim Löschen: {e}")

    def block_site(self, domain, tab):
        """Website sperren"""
        global blocked_sites
        blocked_sites.add(domain)
        save_blocked_sites(blocked_sites)
        tab.setUrl(QUrl("about:blank"))
        self.statusBar().showMessage(f"Website gesperrt: {domain}", 3000)
        QMessageBox.information(self, "Website gesperrt", 
                               f"Die Website '{domain}' wurde gesperrt und wird zukünftig blockiert.")

    def unblock_site(self, domain, tab):
        """Website entsperren"""
        global blocked_sites
        if domain in blocked_sites:
            blocked_sites.remove(domain)
            save_blocked_sites(blocked_sites)
            self.statusBar().showMessage(f"Website entsperrt: {domain}", 3000)
            QMessageBox.information(self, "Website entsperrt", 
                                   f"Die Website '{domain}' wurde entsperrt.")

    def show_website_blocking_menu(self):
        """Zeigt ein Menü für Website-Sperrung/Entsperrung"""
        menu = QMenu(self)
        
        # Aktuelle Website sperren (falls verfügbar)
        current_tab = self.tabs.currentWidget()
        current_url = current_tab.page().url() if current_tab else None
        
        if current_url and current_url.host():
            domain = current_url.host()
            global blocked_sites
            
            if domain in blocked_sites:
                unblock_current_action = menu.addAction(f"🔓 '{domain}' entsperren")
                unblock_current_action.triggered.connect(lambda: self.unblock_specific_site(domain))
            else:
                block_current_action = menu.addAction(f"🚫 '{domain}' sperren")
                block_current_action.triggered.connect(lambda: self.block_specific_site(domain))
            
            menu.addSeparator()
        
        # Gesperrte Websites verwalten
        manage_action = menu.addAction("🔓 Gesperrte Websites verwalten")
        manage_action.triggered.connect(self.show_blocked_sites_manager)
        
        # Website manuell zur Sperrliste hinzufügen
        menu.addSeparator()
        add_manual_action = menu.addAction("➕ Website manuell sperren...")
        add_manual_action.triggered.connect(self.add_website_to_blocklist)
        
        # Menü anzeigen
        menu.exec(self.block_site_btn.mapToGlobal(self.block_site_btn.rect().bottomLeft()))

    def block_specific_site(self, domain):
        """Sperrt eine spezifische Website"""
        global blocked_sites
        blocked_sites.add(domain)
        save_blocked_sites(blocked_sites)
        
        # Aktuelle Website schließen falls sie die gesperrte ist
        current_tab = self.tabs.currentWidget()
        if current_tab and current_tab.page().url().host() == domain:
            current_tab.setUrl(QUrl("about:blank"))
        
        self.statusBar().showMessage(f"Website gesperrt: {domain}", 3000)
        QMessageBox.information(self, "Website gesperrt", 
                               f"Die Website '{domain}' wurde gesperrt.")

    def unblock_specific_site(self, domain):
        """Entsperrt eine spezifische Website"""
        global blocked_sites
        if domain in blocked_sites:
            blocked_sites.remove(domain)
            save_blocked_sites(blocked_sites)
            self.statusBar().showMessage(f"Website entsperrt: {domain}", 3000)
            QMessageBox.information(self, "Website entsperrt", 
                                   f"Die Website '{domain}' wurde entsperrt.")

    def add_website_to_blocklist(self):
        """Fügt eine Website manuell zur Sperrliste hinzu"""
        domain, ok = QInputDialog.getText(self, "Website sperren", 
                                         "Geben Sie die Domain ein, die gesperrt werden soll:\n"
                                         "(z.B. facebook.com, youtube.com)")
        if ok and domain.strip():
            domain = domain.strip().lower()
            # Domain validieren
            if '.' not in domain or ' ' in domain:
                QMessageBox.warning(self, "Ungültige Domain", 
                                   "Bitte geben Sie eine gültige Domain ein (z.B. facebook.com)")
                return
            
            global blocked_sites
            if domain in blocked_sites:
                QMessageBox.information(self, "Bereits gesperrt", 
                                       f"Die Website '{domain}' ist bereits gesperrt.")
                return
            
            blocked_sites.add(domain)
            save_blocked_sites(blocked_sites)
            self.statusBar().showMessage(f"Website gesperrt: {domain}", 3000)
            QMessageBox.information(self, "Website gesperrt", 
                                   f"Die Website '{domain}' wurde zur Sperrliste hinzugefügt.")

    def show_blocked_sites_manager(self):
        """Zeigt einen Dialog zur Verwaltung gesperrter Websites"""
        global blocked_sites
        
        if not blocked_sites:
            QMessageBox.information(self, "Keine gesperrten Websites", 
                                   "Es sind aktuell keine Websites gesperrt.")
            return
        
        # Dialog erstellen
        dialog = QDialog(self)
        dialog.setWindowTitle("Gesperrte Websites verwalten")
        dialog.setModal(True)
        dialog.resize(500, 400)
        
        layout = QVBoxLayout(dialog)
        
        # Liste der gesperrten Sites
        list_widget = QListWidget()
        for site in sorted(blocked_sites):
            item = QListWidgetItem(f"🚫 {site}")
            item.setData(Qt.ItemDataRole.UserRole, site)
            list_widget.addItem(item)
        
        layout.addWidget(list_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        unblock_btn = QPushButton("🔓 Ausgewählte Website entsperren")
        unblock_btn.clicked.connect(lambda: self.unblock_selected_site(list_widget, dialog))
        button_layout.addWidget(unblock_btn)
        
        close_btn = QPushButton("Schließen")
        close_btn.clicked.connect(dialog.close)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        dialog.exec()



    def unblock_selected_site(self, list_widget, dialog):
        """Entsperrt die ausgewählte Website aus der Liste"""
        current_item = list_widget.currentItem()
        if not current_item:
            QMessageBox.warning(dialog, "Keine Auswahl", "Bitte wählen Sie eine Website zum Entsperren aus.")
            return
        
        site = current_item.data(Qt.ItemDataRole.UserRole)
        global blocked_sites
        
        reply = QMessageBox.question(dialog, "Website entsperren", 
                                    f"Website '{site}' wirklich entsperren?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        
        if reply == QMessageBox.StandardButton.Yes:
            blocked_sites.remove(site)
            save_blocked_sites(blocked_sites)
            list_widget.takeItem(list_widget.row(current_item))
            self.statusBar().showMessage(f"Website entsperrt: {site}", 3000)
            
            # Dialog schließen wenn keine Sites mehr übrig
            if list_widget.count() == 0:
                QMessageBox.information(dialog, "Fertig", "Alle Websites wurden entsperrt.")
                dialog.close()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Surfwolf74 | Version 5.0 | by Wolfram Consult GmbH & Co. KG")
        self.resize(1200, 800)
        self.current_color_name = 'lightgreen'
        self.font_scale = 1.0
        self.base_font = QFont("Arial", 10)
        self.js_enabled = True  # Standard: JS aktiviert
        self.security_mode = "normal"
        
        # Farbschema-System - Erweiterte Farbpalette
        self.current_color = "#caff70"  # Standard: Hellgrün
        self.color_themes = {
            # Helle Farben
            "lightblue": "#87ceeb",      # Helles Blau
            "lightgreen": "#caff70",     # Helles Grün (Standard)
            "lightorange": "#ffb347",    # Helles Orange
            "lightgray": "#d3d3d3",      # Helles Grau
            "lightbrown": "#deb887",     # Helles Braun
            "lightyellow": "#ffff99",    # Helles Gelb
            "lightpink": "#ffb6c1",      # Helles Rosa
            "lightpurple": "#dda0dd",    # Helles Lila
            "lightcyan": "#e0ffff",      # Helles Cyan
            "lightcoral": "#f08080",     # Helles Koralle
            # Dunklere/Kräftigere Farben
            "winered": "#722f37",        # Weinrot
            "darkblue": "#191970",       # Dunkelblau (Midnight Blue)
            "forestgreen": "#228b22",    # Waldgrün
            "darkpurple": "#483d8b",     # Dunkellila
            "maroon": "#800000",         # Kastanienbraun
            "navy": "#000080",           # Marine-Blau
            "darkslategray": "#2f4f4f",  # Dunkelschiefer
            "chocolate": "#d2691e",      # Schokoladenbraun
            "darkgoldenrod": "#b8860b",  # Dunkles Goldgelb
            "crimson": "#dc143c"         # Karmesinrot
        }
        
        # Button-Referenzen für spätere Updates
        self.js_btn = None
        self.security_toggle_btn = None
        self.block_site_btn = None
        self.dark_mode_btn = None
        self.website_invert_btn = None
        self.font_smaller_btn = None
        self.font_normal_btn = None
        self.font_larger_btn = None
        
        # Website-Farben invertieren State
        self.website_colors_inverted = False
        
        # BARRIEREFREIHEIT - Accessibility-Einstellungen
        self.font_size_scale = 1.0
        
        # Flag für einmalige Initialisierung
        self.initial_tab_created = False
        
        self.load_config()

        # Initialize drag colors for bookmark buttons
        if hasattr(self, 'dark_mode') and self.dark_mode:
            self.drag_colors = {
                'pressed': "background-color: #5a2d2d; border: 2px solid #aa4444;",
                'dragging': "background-color: #5a5a2d; border: 3px dashed #aaaa44;",
                'drop_zone': "background-color: #2d5a2d; border: 2px solid #44aa44;"
            }
        else:
            self.drag_colors = {
                'pressed': "background-color: #ffcccc; border: 2px solid #ff6666;",
                'dragging': "background-color: #ffffcc; border: 3px dashed #ff9900;",
                'drop_zone': "background-color: #ccffcc; border: 2px solid #66cc66;"
            }

        # Standard: Default-Profil verwenden (normale Browser-Experience)
        if self.security_mode == "normal":
            self.profile = QWebEngineProfile.defaultProfile()
            # Kein Interceptor im Normal-Modus - völlig unberührte Browser-Experience
            self.interceptor = None
            
            # Media-Optimierungen für bessere Video-Kompatibilität (x.com, YouTube, etc.)
            self.profile.settings().setAttribute(
                self.profile.settings().WebAttribute.PluginsEnabled, True
            )
            self.profile.settings().setAttribute(
                self.profile.settings().WebAttribute.JavascriptCanAccessClipboard, True
            )
            # WebGL für Video-Beschleunigung
            self.profile.settings().setAttribute(
                self.profile.settings().WebAttribute.WebGLEnabled, True
            )
            # Hardware-Beschleunigung für Videos
            self.profile.settings().setAttribute(
                self.profile.settings().WebAttribute.Accelerated2dCanvasEnabled, True
            )
            
        else:
            # Nur im Strict-Modus eigenes Profil mit Sicherheitsfeatures
            self.profile = QWebEngineProfile("SurfWolf74StrictProfile", self)
            
            # Privacy-optimierte Profil-Einstellungen für browseraudit.com
            self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)  # Keine persistenten Cookies
            self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)  # Nur RAM-Cache
            self.profile.setHttpCacheMaximumSize(0)  # Minimaler Cache
            
            # Download-Pfad sicher setzen
            self.profile.setDownloadPath(tempfile.gettempdir())
            
            # Spell-Check deaktivieren (Privacy)
            self.profile.setSpellCheckEnabled(False)
            
            self.interceptor = DNTInterceptor(self.security_mode)
            self.profile.setUrlRequestInterceptor(self.interceptor)
        
        # User Agent für Website-Kompatibilität (Chrome 131)
        self.profile.setHttpUserAgent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        )

        self.setup_ui()
        
        # Theme anwenden
        self.apply_theme()
        
        # Statusleiste mit dezenten Credits einrichten
        status_bar = QStatusBar()
        self.setStatusBar(status_bar)
        
        # Dezenter Credit-Hinweis rechts in der Statusleiste
        credit_label = QLabel("SurfWolf74, Konzeption und Programmierung: Rob de Roy")
        credit_label.setStyleSheet("QLabel { color: #888888; font-size: 10px; padding-right: 10px; }")
        credit_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        status_bar.addPermanentWidget(credit_label)
        
        # Screenshot-Schutz NACH der UI-Erstellung aktivieren

        
        # Gespeicherte Fensterposition/Größe wiederherstellen
        if getattr(self, '_saved_geometry', None):
            geo = self._saved_geometry
            self.move(geo.get('x', 100), geo.get('y', 100))
            self.resize(geo.get('width', 1200), geo.get('height', 800))
            if geo.get('maximized', False):
                self.showMaximized()

        # Den ersten Tab mit minimaler Verzögerung erstellen (50ms für Profile-Stabilität)
        QTimer.singleShot(50, self.create_initial_tab)

    def create_initial_tab(self):
        """Erstellt den ersten Tab mit Verzögerung für bessere Font-Qualität"""
        if not self.initial_tab_created:
            self.initial_tab_created = True
            self.add_new_tab()

    def load_config(self):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                config = json.load(f)
            self.js_enabled = config.get('js_enabled', True)
            self.security_mode = config.get('security_mode', 'normal')
            self.dark_mode = config.get('dark_mode', False)
            self.website_colors_inverted = config.get('website_colors_inverted', False)
            self.current_color_name = config.get('color_theme', 'lightgreen')
            self.font_size_scale = config.get('font_size_scale', 1.0)
            # Fensterposition und -größe
            self._saved_geometry = config.get('window_geometry', None)
        except Exception:
            self.js_enabled = True
            self.security_mode = 'normal'
            self.dark_mode = False
            self.website_colors_inverted = False
            self.current_color_name = 'lightgreen'
            self.font_size_scale = 1.0
            self._saved_geometry = None

    def save_config(self):
        try:
            config = {
                'js_enabled': self.js_enabled,
                'security_mode': self.security_mode,
                'dark_mode': self.dark_mode,
                'website_colors_inverted': self.website_colors_inverted,
                'color_theme': getattr(self, 'current_color_name', 'lightgreen'),
                'font_size_scale': self.font_size_scale,
                'window_geometry': {
                    'x': self.x(), 'y': self.y(),
                    'width': self.width(), 'height': self.height(),
                    'maximized': self.isMaximized()
                }
            }
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Config speichern fehlgeschlagen: {e}")

    # Theme-Farbpaletten: Dark und Light
    THEME_COLORS = {
        True: {  # Dark Mode
            'main_bg': '#2b2b2b', 'main_fg': '#ffffff',
            'widget_bg': '#2b2b2b', 'widget_fg': '#ffffff',
            'toolbar_start': '#3c3c3c', 'toolbar_border': '#555555', 'toolbar_fg': '#ffffff',
            'input_bg': '#404040', 'input_border': '#555555', 'input_fg': '#ffffff',
            'btn_bg': '#404040', 'btn_border': '#555555', 'btn_fg': '#ffffff',
            'btn_hover_bg': '#4a4a4a', 'btn_hover_border': '#777777',
            'btn_pressed_bg': '#353535',
            'tab_pane_border': '#555555', 'tab_pane_bg': '#2b2b2b',
            'tab_bg': '#404040', 'tab_border': '#555555', 'tab_fg': '#ffffff',
            'tab_hover_bg': '#4a4a4a', 'tab_selected_fg': '',
            'status_bg': '#3c3c3c', 'status_border': '#555555', 'status_fg': '#cccccc',
            'label_fg': '#ffffff',
            'dark_btn_bg': '#1a1a1a', 'dark_btn_fg': '#ffd700',
            'fav_btn_bg': '#0066cc',
            'js_on_bg': '#2d5a2d', 'js_off_bg': '#5a2d2d',
            'block_btn_bg': '#5a2d2d',
            'invert_active': '#5a5a2d', 'invert_inactive': '#404040', 'invert_fg': 'white',
            'font_btn_bg': '#2d4a5a', 'font_normal_bg': '#4a4a4a',
            'drag_pressed': "background-color: #5a2d2d; border: 2px solid #aa4444;",
            'drag_dragging': "background-color: #5a5a2d; border: 3px dashed #aaaa44;",
            'drag_drop': "background-color: #2d5a2d; border: 2px solid #44aa44;",
        },
        False: {  # Light Mode
            'main_bg': '#ffffff', 'main_fg': '#000000',
            'widget_bg': '#f8f9fa', 'widget_fg': '#000000',
            'toolbar_start': '#e3f0ff', 'toolbar_border': '#cccccc', 'toolbar_fg': '#000000',
            'input_bg': '#ffffff', 'input_border': '#cccccc', 'input_fg': '#000000',
            'btn_bg': '#f8f9fa', 'btn_border': '#cccccc', 'btn_fg': '#000000',
            'btn_hover_bg': '#e9ecef', 'btn_hover_border': '#aaaaaa',
            'btn_pressed_bg': '#dee2e6',
            'tab_pane_border': '#cccccc', 'tab_pane_bg': '#ffffff',
            'tab_bg': '#f8f9fa', 'tab_border': '#cccccc', 'tab_fg': '#000000',
            'tab_hover_bg': '#e9ecef', 'tab_selected_fg': 'color: #ffffff;',
            'status_bg': '#f0f0f0', 'status_border': '#cccccc', 'status_fg': '#333333',
            'label_fg': '#000000',
            'dark_btn_bg': '#ffd700', 'dark_btn_fg': '#000000',
            'fav_btn_bg': '#007bff',
            'js_on_bg': '#4CAF50', 'js_off_bg': '#f44336',
            'block_btn_bg': '#f44336',
            'invert_active': '#ffc107', 'invert_inactive': '#f8f9fa', 'invert_fg': 'black',
            'font_btn_bg': '#17a2b8', 'font_normal_bg': '#6c757d',
            'drag_pressed': "background-color: #ffcccc; border: 2px solid #ff6666;",
            'drag_dragging': "background-color: #ffffcc; border: 3px dashed #ff9900;",
            'drag_drop': "background-color: #ccffcc; border: 2px solid #66cc66;",
        }
    }

    def apply_theme(self):
        """Wendet das aktuelle Theme (Light/Dark Mode) auf das gesamte Interface an"""
        c = self.THEME_COLORS[self.dark_mode]
        
        app_style = f"""
            QMainWindow {{ background-color: {c['main_bg']}; color: {c['main_fg']}; }}
            QWidget {{ background-color: {c['widget_bg']}; color: {c['widget_fg']}; font-family: 'Segoe UI', 'Arial', sans-serif; }}
            QToolBar {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 {c['toolbar_start']}, stop:1 {self.current_color}); border: 1px solid {c['toolbar_border']}; spacing: 3px; color: {c['toolbar_fg']}; }}
            QLineEdit {{ background-color: {c['input_bg']}; border: 2px solid {c['input_border']}; border-radius: 5px; padding: 5px; color: {c['input_fg']}; font-size: 14px; }}
            QLineEdit:focus {{ border-color: #0078d4; }}
            QPushButton {{ background-color: {c['btn_bg']}; border: 1px solid {c['btn_border']}; border-radius: 4px; padding: 5px 10px; color: {c['btn_fg']}; font-weight: bold; }}
            QPushButton:hover {{ background-color: {c['btn_hover_bg']}; border-color: {c['btn_hover_border']}; }}
            QPushButton:pressed {{ background-color: {c['btn_pressed_bg']}; }}
            QTabWidget::pane {{ border: 1px solid {c['tab_pane_border']}; background-color: {c['tab_pane_bg']}; }}
            QTabBar::tab {{ background-color: {c['tab_bg']}; border: 1px solid {c['tab_border']}; padding: 8px 12px; margin-right: 2px; color: {c['tab_fg']}; }}
            QTabBar::tab:selected {{ background-color: #0078d4; border-color: #0078d4; {c['tab_selected_fg']} }}
            QTabBar::tab:hover {{ background-color: {c['tab_hover_bg']}; }}
            QStatusBar {{ background-color: {c['status_bg']}; border-top: 1px solid {c['status_border']}; color: {c['status_fg']}; }}
            QLabel {{ color: {c['label_fg']}; }}
        """
        self.setStyleSheet(app_style)
        
        # Button-Styles aktualisieren
        if hasattr(self, 'dark_mode_btn') and self.dark_mode_btn:
            self.dark_mode_btn.setText("☀️ Light" if self.dark_mode else "🌙 Dark")
            self.dark_mode_btn.setStyleSheet(f"QPushButton {{ background-color: {c['dark_btn_bg']}; color: {c['dark_btn_fg']}; font-weight: bold; }}")
        
        if hasattr(self, 'add_fav_btn') and self.add_fav_btn:
            self.add_fav_btn.setStyleSheet(f"QPushButton {{ background-color: {c['fav_btn_bg']}; color: white; font-weight: bold; padding: 5px 10px; }}")
        
        if hasattr(self, 'js_btn') and self.js_btn:
            js_bg = c['js_on_bg'] if self.js_enabled else c['js_off_bg']
            self.js_btn.setStyleSheet(f"QPushButton {{ background-color: {js_bg}; color: white; }}")
        
        if hasattr(self, 'block_site_btn') and self.block_site_btn:
            self.block_site_btn.setStyleSheet(f"QPushButton {{ background-color: {c['block_btn_bg']}; color: white; font-weight: bold; padding: 5px 10px; }}")
        
        if hasattr(self, 'website_invert_btn') and self.website_invert_btn:
            self.website_invert_btn.setText("🌗 Farben Normal" if self.website_colors_inverted else "🌗 Farben Invert")
            inv_color = c['invert_active'] if self.website_colors_inverted else c['invert_inactive']
            self.website_invert_btn.setStyleSheet(f"QPushButton {{ background-color: {inv_color}; color: {c['invert_fg']}; font-weight: bold; }}")
        
        for btn_name in ('font_smaller_btn', 'font_larger_btn'):
            btn = getattr(self, btn_name, None)
            if btn:
                btn.setStyleSheet(f"QPushButton {{ background-color: {c['font_btn_bg']}; color: white; font-weight: bold; padding: 5px 8px; }}")
        
        if hasattr(self, 'font_normal_btn') and self.font_normal_btn:
            self.font_normal_btn.setStyleSheet(f"QPushButton {{ background-color: {c['font_normal_bg']}; color: white; font-weight: bold; padding: 5px 8px; }}")
        
        self.drag_colors = {
            'pressed': c['drag_pressed'],
            'dragging': c['drag_dragging'],
            'drop_zone': c['drag_drop']
        }
        
        # Farbbuttons mit dem aktuellen Theme aktualisieren
        self.update_color_buttons_theme()

    def toggle_dark_mode(self):
        """Wechselt zwischen Dark und Light Mode"""
        self.dark_mode = not self.dark_mode
        self.apply_theme()
        self.save_config()
        
        # Bookmark-Buttons neu laden, damit sie die neuen Farben bekommen
        self.load_bookmarks()
        
        print(f"{'🌙 Dark Mode aktiviert' if self.dark_mode else '☀️ Light Mode aktiviert'}")

    def toggle_website_colors(self):
        """Invertiert die Farben aller Websites für bessere Lesbarkeit bei hellen Seiten"""
        self.website_colors_inverted = not self.website_colors_inverted
        self.save_config()
        
        # CSS für Farb-Inversion auf allen Tabs anwenden
        invert_css = """
        html {
            filter: invert(1) hue-rotate(180deg) !important;
        }
        img, video, iframe, svg, canvas, embed, object {
            filter: invert(1) hue-rotate(180deg) !important;
        }
        [style*="background-image"] {
            filter: invert(1) hue-rotate(180deg) !important;
        }
        """ if self.website_colors_inverted else ""
        
        # Auf alle Tabs anwenden
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if hasattr(tab, 'page'):
                if self.website_colors_inverted:
                    tab.page().runJavaScript(f"""
                        // Altes Style-Element entfernen falls vorhanden
                        var oldStyle = document.getElementById('surfwolf-invert-colors');
                        if (oldStyle) oldStyle.remove();
                        
                        // Neues Style-Element erstellen
                        var style = document.createElement('style');
                        style.id = 'surfwolf-invert-colors';
                        style.type = 'text/css';
                        var css = `{invert_css}`;
                        
                        // CSS sicher einfügen
                        if (style.styleSheet) {{
                            style.styleSheet.cssText = css;
                        }} else {{
                            style.appendChild(document.createTextNode(css));
                        }}
                        
                        document.head.appendChild(style);
                    """)
                else:
                    tab.page().runJavaScript("""
                        var style = document.getElementById('surfwolf-invert-colors');
                        if (style) style.remove();
                    """)
        
        # Button aktualisieren
        if hasattr(self, 'website_invert_btn') and self.website_invert_btn:
            self.website_invert_btn.setText("🌗 Farben Normal" if self.website_colors_inverted else "🌗 Farben Invert")
            if self.dark_mode:
                color = "#5a5a2d" if self.website_colors_inverted else "#404040"
            else:
                color = "#ffc107" if self.website_colors_inverted else "#f8f9fa"
            self.website_invert_btn.setStyleSheet(f"QPushButton {{ background-color: {color}; color: {'white' if self.dark_mode else 'black'}; font-weight: bold; }}")
        
        print(f"{'🌗 Website-Farben invertiert' if self.website_colors_inverted else '🌗 Website-Farben normal'}")

    def apply_website_inversion_to_tab(self, tab):
        """Wendet die Farb-Inversion auf einen spezifischen Tab an (für neue Tabs)"""
        if not self.website_colors_inverted or not hasattr(tab, 'page'):
            return
        
        invert_css = """
        html {
            filter: invert(1) hue-rotate(180deg) !important;
        }
        img, video, iframe, svg, canvas, embed, object {
            filter: invert(1) hue-rotate(180deg) !important;
        }
        [style*="background-image"] {
            filter: invert(1) hue-rotate(180deg) !important;
        }
        """
        
        tab.page().runJavaScript(f"""
            // Altes Style-Element entfernen falls vorhanden
            var oldStyle = document.getElementById('surfwolf-invert-colors');
            if (oldStyle) oldStyle.remove();
            
            // Neues Style-Element erstellen
            var style = document.createElement('style');
            style.id = 'surfwolf-invert-colors';
            style.type = 'text/css';
            var css = `{invert_css}`;
            
            // CSS sicher einfügen
            if (style.styleSheet) {{
                style.styleSheet.cssText = css;
            }} else {{
                style.appendChild(document.createTextNode(css));
            }}
            
            document.head.appendChild(style);
        """)



    def update_color_buttons_theme(self):
        """Aktualisiert die Farbbuttons für das aktuelle Theme (Dark/Light Mode)"""
        if not hasattr(self, 'color_buttons'):
            return
        
        # Theme-abhängige Rahmenfarben
        if self.dark_mode:
            normal_border = "#555555"  # Dunkler Rahmen für Dark Mode
            hover_border = "#0078d4"   # Hellblau für Hover
            selected_border = "#0078d4" # Hellblau für Selektion
        else:
            normal_border = "#ffffff"  # Weißer Rahmen für Light Mode
            hover_border = "#007bff"   # Blau für Hover  
            selected_border = "#007bff" # Blau für Selektion
        
        # Alle Farbbuttons aktualisieren
        for color_name, btn in self.color_buttons.items():
            color_code = self.color_themes[color_name]
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color_code};
                    border: 2px solid {normal_border};
                    border-radius: 9px;
                    margin: 1px;
                }}
                QPushButton:hover {{
                    border: 2px solid {hover_border};
                }}
                QPushButton:pressed {{
                    border: 3px solid {hover_border};
                }}
            """)

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        # Navigation
        nav_widget = QWidget()
        nav_layout = QHBoxLayout(nav_widget)
        nav_layout.setContentsMargins(5, 5, 5, 5)
        nav_layout.setSpacing(5)

        back_btn = QPushButton("←")
        back_btn.setFixedSize(35, 30)
        back_btn.clicked.connect(self.go_back)
        nav_layout.addWidget(back_btn)

        forward_btn = QPushButton("→")
        forward_btn.setFixedSize(35, 30)
        forward_btn.clicked.connect(self.go_forward)
        nav_layout.addWidget(forward_btn)

        reload_btn = QPushButton("↻")
        reload_btn.setFixedSize(35, 30)
        reload_btn.clicked.connect(self.reload_page)
        nav_layout.addWidget(reload_btn)

        # Home Button
        home_btn = QPushButton("🏠")
        home_btn.setFixedSize(35, 30)
        home_btn.clicked.connect(self.go_home)
        home_btn.setToolTip("DuckDuckGo")
        nav_layout.addWidget(home_btn)

        # Neuer Tab Button
        new_tab_btn = QPushButton("+")
        new_tab_btn.setFixedSize(35, 30)
        new_tab_btn.clicked.connect(lambda: self.add_new_tab())
        nav_layout.addWidget(new_tab_btn)

        self.url_bar = QLineEdit()
        self.url_bar.setPlaceholderText("URL eingeben oder suchen...")
        self.url_bar.returnPressed.connect(self.navigate_to_url)
        nav_layout.addWidget(self.url_bar, stretch=1)

        # Extern öffnen Button (vergrößert und besser sichtbar, erweitert nach links)
        external_btn = QPushButton("🌐 Extern")
        external_btn.setMinimumSize(80, 30)
        external_btn.setMaximumSize(120, 30)
        external_btn.clicked.connect(self.open_in_external_browser)
        external_btn.setToolTip("Aktuelle Seite in externem Browser öffnen (Strg+E)")
        external_btn.setStyleSheet("QPushButton { background-color: #28a745; color: white; font-weight: bold; border: 2px solid #ffffff; }")
        external_btn.setShortcut("Ctrl+E")
        external_btn.setCursor(Qt.CursorShape.PointingHandCursor)  # Pointer-Cursor bei Hover
        nav_layout.addWidget(external_btn)

        # Farbauswahl-Buttons in der Navigationsleiste
        # Farbauswahl-Label
        color_label = QPushButton("🎨")
        color_label.setFixedSize(30, 30)
        color_label.setToolTip("Farbschema auswählen")
        color_label.setStyleSheet("QPushButton { background: transparent; border: none; font-size: 16px; }")
        nav_layout.addWidget(color_label)
        
        # Farbbuttons erstellen - Erweiterte Palette mit 20 Farben
        self.color_buttons = {}
        colors = [
            # Helle Farben (erste Reihe)
            ("lightblue", "#87ceeb", "Helles Blau"),
            ("lightgreen", "#caff70", "Helles Grün"),
            ("lightorange", "#ffb347", "Helles Orange"),
            ("lightgray", "#d3d3d3", "Helles Grau"),
            ("lightbrown", "#deb887", "Helles Braun"),
            ("lightyellow", "#ffff99", "Helles Gelb"),
            ("lightpink", "#ffb6c1", "Helles Rosa"),
            ("lightpurple", "#dda0dd", "Helles Lila"),
            ("lightcyan", "#e0ffff", "Helles Cyan"),
            ("lightcoral", "#f08080", "Helles Koralle"),
            # Dunklere/Kräftigere Farben (zweite Reihe)
            ("winered", "#722f37", "Weinrot"),
            ("darkblue", "#191970", "Dunkelblau"),
            ("forestgreen", "#228b22", "Waldgrün"),
            ("darkpurple", "#483d8b", "Dunkellila"),
            ("maroon", "#800000", "Kastanienbraun"),
            ("navy", "#000080", "Marine-Blau"),
            ("darkslategray", "#2f4f4f", "Dunkelschiefer"),
            ("chocolate", "#d2691e", "Schokoladenbraun"),
            ("darkgoldenrod", "#b8860b", "Dunkles Goldgelb"),
            ("crimson", "#dc143c", "Karmesinrot")
        ]
        
        for color_name, color_code, tooltip in colors:
            btn = QPushButton()
            btn.setFixedSize(18, 18)  # Etwas kleiner für mehr Farben
            btn.setToolTip(f"Farbschema: {tooltip}")
            # Theme-abhängige Rahmenfarbe wird in update_color_buttons_theme() gesetzt
            btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {color_code};
                    border: 2px solid {"#555555" if self.dark_mode else "#ffffff"};
                    border-radius: 9px;
                    margin: 1px;
                }}
                QPushButton:hover {{
                    border: 2px solid {"#0078d4" if self.dark_mode else "#007bff"};
                }}
                QPushButton:pressed {{
                    border: 3px solid {"#0078d4" if self.dark_mode else "#007bff"};
                }}
            """)
            btn.clicked.connect(lambda checked, name=color_name: self.change_color_theme(name))
            self.color_buttons[color_name] = btn
            nav_layout.addWidget(btn)
        
        # Gespeichertes Farbschema wiederherstellen
        saved_color = getattr(self, 'current_color_name', 'lightgreen')
        if saved_color in self.color_themes:
            self.update_color_button_selection(saved_color)
            self.change_color_theme(saved_color)
        else:
            self.update_color_button_selection('lightgreen')
            self.change_color_theme('lightgreen')

        layout.addWidget(nav_widget)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.update_url_bar)
        layout.addWidget(self.tabs)

        # Toolbars
        self.create_toolbars()

        # Erster Tab wird mit Verzögerung erstellt (siehe create_initial_tab)
        # Nicht hier: self.add_new_tab()

    def create_toolbars(self):
        # Erste Toolbar für Bedienelemente (links)
        self.main_toolbar = QToolBar("Bedienelemente")
        self.addToolBar(self.main_toolbar)
        
        # Zweite Toolbar für Bookmarks (rechts) 
        self.bookmarks_toolbar = QToolBar("Bookmarks")
        self.addToolBar(self.bookmarks_toolbar)
        
        # LINKS: Alle Options-Elemente der GUI in der ersten Toolbar
        
        # Font Size Controls
        self.font_smaller_btn = QPushButton("A-")
        self.font_smaller_btn.clicked.connect(self.decrease_font_size)
        self.font_smaller_btn.setToolTip("Schriftgröße verkleinern")
        self.font_smaller_btn.setStyleSheet("QPushButton { background-color: #17a2b8; color: white; font-weight: bold; padding: 5px 8px; }")
        self.main_toolbar.addWidget(self.font_smaller_btn)
        
        self.font_normal_btn = QPushButton("A")
        self.font_normal_btn.clicked.connect(self.reset_font_size)
        self.font_normal_btn.setToolTip("Schriftgröße zurücksetzen")
        self.font_normal_btn.setStyleSheet("QPushButton { background-color: #6c757d; color: white; font-weight: bold; padding: 5px 8px; }")
        self.main_toolbar.addWidget(self.font_normal_btn)
        
        self.font_larger_btn = QPushButton("A+")
        self.font_larger_btn.clicked.connect(self.increase_font_size)
        self.font_larger_btn.setToolTip("Schriftgröße vergrößern")
        self.font_larger_btn.setStyleSheet("QPushButton { background-color: #17a2b8; color: white; font-weight: bold; padding: 5px 8px; }")
        self.main_toolbar.addWidget(self.font_larger_btn)
        
        # Tastatur-Hilfe Button
        keyboard_info_btn = QPushButton("⌨️ Tastatur-Hilfe")
        keyboard_info_btn.clicked.connect(self.show_keyboard_help)
        keyboard_info_btn.setToolTip("Tastaturkürzel und Navigation anzeigen")
        keyboard_info_btn.setStyleSheet("QPushButton { background-color: #6f42c1; color: white; font-weight: bold; padding: 5px 10px; }")
        self.main_toolbar.addWidget(keyboard_info_btn)
        
        # Separator zwischen Font-Controls und anderen Optionen
        self.main_toolbar.addSeparator()

        # JS Toggle Button
        self.js_btn = QPushButton("JS " + ("An" if self.js_enabled else "Aus"))
        self.js_btn.clicked.connect(self.toggle_javascript)
        self.js_btn.setToolTip("JavaScript umschalten")
        self.js_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }" if self.js_enabled else "QPushButton { background-color: #f44336; color: white; }")
        self.main_toolbar.addWidget(self.js_btn)

        # Security Toggle Button
        self.security_toggle_btn = QPushButton("Sicherheit: " + ("Strikt" if self.security_mode == 'strict' else "Normal"))
        self.security_toggle_btn.clicked.connect(self.toggle_security_mode)
        self.security_toggle_btn.setToolTip("Zwischen sehr restriktivem und normalem Sicherheitsmodus umschalten")
        self.main_toolbar.addWidget(self.security_toggle_btn)

        # Dark Mode Toggle Button
        self.dark_mode_btn = QPushButton("🌙 Dark" if not self.dark_mode else "☀️ Light")
        self.dark_mode_btn.clicked.connect(self.toggle_dark_mode)
        self.dark_mode_btn.setToolTip("Zwischen Dark Mode und Light Mode umschalten")
        if self.dark_mode:
            self.dark_mode_btn.setStyleSheet("QPushButton { background-color: #1a1a1a; color: #ffd700; font-weight: bold; }")
        else:
            self.dark_mode_btn.setStyleSheet("QPushButton { background-color: #ffd700; color: #000000; font-weight: bold; }")
        self.main_toolbar.addWidget(self.dark_mode_btn)

        # Website-Farben invertieren Button
        self.website_invert_btn = QPushButton("🌗 Farben Invert" if not self.website_colors_inverted else "🌗 Farben Normal")
        self.website_invert_btn.clicked.connect(self.toggle_website_colors)
        self.website_invert_btn.setToolTip("Website-Farben invertieren für bessere Lesbarkeit bei hellen Seiten")
        if self.dark_mode:
            color = "#5a5a2d" if self.website_colors_inverted else "#404040"
        else:
            color = "#ffc107" if self.website_colors_inverted else "#f8f9fa"
        self.website_invert_btn.setStyleSheet(f"QPushButton {{ background-color: {color}; color: {'white' if self.dark_mode else 'black'}; font-weight: bold; }}")
        self.main_toolbar.addWidget(self.website_invert_btn)

        # Website-Sperr-Button
        self.block_site_btn = QPushButton("🚫 Websites verwalten")
        self.block_site_btn.clicked.connect(self.show_website_blocking_menu)
        self.block_site_btn.setToolTip("Websites sperren/entsperren")
        self.block_site_btn.setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 5px 10px; }")
        self.main_toolbar.addWidget(self.block_site_btn)

        # === BOOKMARKS TOOLBAR (SEPARAT VERSCHIEBBAR) ===
        
        # Zu Favoriten hinzufügen Button in der Bookmarks-Toolbar
        self.add_fav_btn = QPushButton("⭐ Zu Favoriten")
        self.add_fav_btn.setToolTip("Aktuelle Seite zu Favoriten hinzufügen")
        self.add_fav_btn.clicked.connect(self.add_bookmark)
        self.add_fav_btn.setStyleSheet("QPushButton { background-color: #007bff; color: white; font-weight: bold; padding: 5px 10px; }")
        self.bookmarks_toolbar.addWidget(self.add_fav_btn)

        # Position für Bookmark-Einfügung in der Bookmarks-Toolbar merken
        self.bookmark_insert_position = len(self.bookmarks_toolbar.actions())

        # Favoriten laden - sie werden an der richtigen Position eingefügt
        self.load_bookmarks()
        
        # Die alte Accessibility-Toolbar wird nicht mehr benötigt, da alles in der Haupttoolbar ist

    # LEGACY: create_accessibility_toolbar() - Funktionalität wurde in create_toolbars() integriert

    def increase_font_size(self):
        """Vergrößert die Schriftgröße"""
        self.font_size_scale = min(self.font_size_scale + 0.1, 2.0)  # Maximum 200%
        self.apply_font_size_to_all_tabs()
        self.save_config()
        self.statusBar().showMessage(f"Schriftgröße: {int(self.font_size_scale * 100)}%", 2000)

    def decrease_font_size(self):
        """Verkleinert die Schriftgröße"""
        self.font_size_scale = max(self.font_size_scale - 0.1, 0.5)  # Minimum 50%
        self.apply_font_size_to_all_tabs()
        self.save_config()
        self.statusBar().showMessage(f"Schriftgröße: {int(self.font_size_scale * 100)}%", 2000)

    def reset_font_size(self):
        """Setzt die Schriftgröße zurück"""
        self.font_size_scale = 1.0
        self.apply_font_size_to_all_tabs()
        self.save_config()
        self.statusBar().showMessage("Schriftgröße zurückgesetzt", 2000)

    def apply_font_size_to_all_tabs(self):
        """Wendet die aktuelle Schriftgröße auf alle Tabs an"""
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if tab:
                tab.setZoomFactor(self.font_size_scale)

    def show_keyboard_help(self):
        """Zeigt Tastaturkürzel und Navigation-Hilfe"""
        QMessageBox.information(self, "Tastatur-Navigation", 
                               "⌨️ TASTATURKÜRZEL:\n\n"
                               "• Tab: Nächstes Element\n"
                               "• Shift + Tab: Vorheriges Element\n"
                               "• Enter: Link/Button aktivieren\n"
                               "• Leertaste: Seite nach unten scrollen\n"
                               "• Shift + Leertaste: Seite nach oben scrollen\n"
                               "• Pfeiltasten: Navigation in Listen/Menüs\n"
                               "• Strg + F: Suchen auf der Seite\n"
                               "• Strg + Plus/Minus: Zoom ändern\n"
                               "• Strg + 0: Zoom zurücksetzen\n"
                               "• F6: Zwischen Browser-Bereichen wechseln\n\n"
                               "🔍 Die meisten Websites unterstützen diese Standards!")

    def change_color_theme(self, color_name):
        """Ändert das Farbschema der Anwendung"""
        if color_name in self.color_themes:
            self.current_color = self.color_themes[color_name]
            self.current_color_name = color_name
            # Theme neu anwenden damit Farbschema berücksichtigt wird
            self.apply_theme()
            self.update_color_button_selection(color_name)
            self.save_config()
            self.statusBar().showMessage(f"Farbschema geändert zu: {color_name.title()}", 2000)

    def update_color_button_selection(self, selected_color):
        """Aktualisiert die Auswahl der Farbbuttons"""
        # Theme-abhängige Rahmenfarben
        if self.dark_mode:
            normal_border = "#555555"
            hover_border = "#0078d4"
            selected_border = "#0078d4"
            selected_hover = "#005bb5"
        else:
            normal_border = "#ffffff"
            hover_border = "#007bff"
            selected_border = "#007bff"
            selected_hover = "#0056b3"
        
        for color_name, btn in self.color_buttons.items():
            color_code = self.color_themes[color_name]
            if color_name == selected_color:
                # Ausgewählter Button mit dickerem Border
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {color_code};
                        border: 3px solid {selected_border};
                        border-radius: 10px;
                        margin: 2px;
                    }}
                    QPushButton:hover {{
                        border: 3px solid {selected_hover};
                    }}
                """)
            else:
                # Normale Buttons
                btn.setStyleSheet(f"""
                    QPushButton {{
                        background-color: {color_code};
                        border: 2px solid {normal_border};
                        border-radius: 10px;
                        margin: 2px;
                    }}
                    QPushButton:hover {{
                        border: 2px solid {hover_border};
                    }}
                    QPushButton:pressed {{
                        border: 3px solid {hover_border};
                    }}
                """)

    def toggle_javascript(self):
        self.js_enabled = not self.js_enabled
        # Button-Text und Farbe aktualisieren
        self.js_btn.setText("JS " + ("An" if self.js_enabled else "Aus"))
        self.js_btn.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; }" if self.js_enabled else "QPushButton { background-color: #f44336; color: white; }")
        # Alle offenen Tabs aktualisieren
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if tab:
                try:
                    settings = tab.page().settings()
                    settings.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, self.js_enabled)
                    tab.reload()
                except Exception as e:
                    print(f"JS Toggle Fehler für Tab {i}: {e}")
        self.statusBar().showMessage(f"JavaScript {'aktiviert' if self.js_enabled else 'deaktiviert'}", 3000)

    def toggle_security_mode(self):
        old_mode = self.security_mode
        self.security_mode = 'normal' if self.security_mode == 'strict' else 'strict'
        # Button-Text aktualisieren
        self.security_toggle_btn.setText("Sicherheit: " + ("Strikt" if self.security_mode == 'strict' else "Normal"))
        # Profil komplett wechseln je nach Modus
        if self.security_mode == "normal":
            self.profile = QWebEngineProfile.defaultProfile()
            self.interceptor = None
        else:
            self.profile = QWebEngineProfile("SurfWolf74StrictProfile", self)
            
            # Privacy-optimierte Profil-Einstellungen für browseraudit.com
            self.profile.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
            self.profile.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
            self.profile.setHttpCacheMaximumSize(0)
            
            # Download-Pfad sicher setzen
            self.profile.setDownloadPath(tempfile.gettempdir())
            
            # Spell-Check deaktivieren (Privacy)
            self.profile.setSpellCheckEnabled(False)
            
            # Standard Chrome User Agent ohne Browser-spezifische Signatur
            self.profile.setHttpUserAgent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )
            self.interceptor = DNTInterceptor(self.security_mode)
            self.profile.setUrlRequestInterceptor(self.interceptor)
        # Alle bestehenden Tabs müssen neu erstellt werden mit dem neuen Profil
        current_urls = []
        current_index = self.tabs.currentIndex()
        for i in range(self.tabs.count()):
            tab = self.tabs.widget(i)
            if tab:
                current_urls.append(tab.url().toString())
        while self.tabs.count() > 0:
            widget = self.tabs.widget(0)
            self.tabs.removeTab(0)
            widget.deleteLater()
        for i, url in enumerate(current_urls):
            if i == 0 and not url:
                self.add_new_tab()
            else:
                self.add_new_tab(url)
        if current_index < self.tabs.count():
            self.tabs.setCurrentIndex(current_index)
        self.statusBar().showMessage(
            f"Sicherheitsmodus: {'BrowserAudit-Optimiert (Anti-Fingerprinting + Strict CSP)' if self.security_mode == 'strict' else 'Normal (Standard-Browser-Verhalten)'}", 
            5000
        )

    def go_back(self):
        tab = self.tabs.currentWidget()
        if tab and tab.history().canGoBack():
            tab.back()

    def go_forward(self):
        tab = self.tabs.currentWidget()
        if tab and tab.history().canGoForward():
            tab.forward()

    def reload_page(self):
        tab = self.tabs.currentWidget()
        if tab:
            tab.reload()

    def go_home(self):
        """Navigiert zu DuckDuckGo"""
        tab = self.tabs.currentWidget()
        if tab:
            tab.setUrl(QUrl("https://duckduckgo.com"))
            # URL-Leiste wird automatisch durch urlChanged Signal aktualisiert

    def open_in_external_browser(self):
        """Öffnet die aktuelle Seite in einem externen Browser"""
        current_tab = self.tabs.currentWidget()
        if not current_tab:
            QMessageBox.information(self, "Kein Tab", "Kein aktiver Tab verfügbar.")
            return
        
        current_url = current_tab.url().toString()
        if not current_url or current_url == "about:blank":
            self.statusBar().showMessage("Keine URL zum Öffnen verfügbar", 3000)
            QMessageBox.warning(self, "Keine URL", "Keine gültige URL zum Öffnen verfügbar.")
            return
        
        try:
            # Spezielle Behandlung für x.com Videos - einfacher Hinweis
            if 'x.com' in current_url or 'twitter.com' in current_url:
                self.statusBar().showMessage("🎬 X.com/Twitter Videos funktionieren im externen Browser besser", 4000)
            
            webbrowser.open(current_url)
            self.statusBar().showMessage(f"🌐 Seite in externem Browser geöffnet: {current_url[:60]}...", 5000)
            
        except Exception as e:
            error_msg = f"Fehler beim Öffnen im externem Browser: {e}"
            self.statusBar().showMessage(error_msg, 5000)
            QMessageBox.critical(self, "Fehler", error_msg)

    def navigate_to_bookmark(self, url):
        """Sichere Navigation zu Lesezeichen mit Sperrprüfung"""
        qurl = QUrl(url)
        
        # WEBSITE-SPERRUNG: Prüfung BEVOR Navigation startet
        if qurl.host() and is_site_blocked(qurl.host()):
            host = qurl.host().lower()
            self.statusBar().showMessage(f"🚫 Zugriff verweigert: {host} ist gesperrt", 5000)
            QMessageBox.warning(self, "Website gesperrt", 
                               f"Das Lesezeichen '{host}' ist gesperrt und kann nicht aufgerufen werden.\n\n"
                               f"Verwenden Sie den roten Button zum Entsperren.")
            return
        
        tab = self.tabs.currentWidget()
        if tab:
            tab.setUrl(qurl)


    def toggle_dev_tools(self):
        tab = self.tabs.currentWidget()
        if tab:
            # Developer Tools in neuem Fenster öffnen
            dev_view = QWebEngineView()
            tab.page().setDevToolsPage(dev_view.page())
            dev_view.show()
            dev_view.setWindowTitle("Developer Tools - SurfWolf74")
            dev_view.resize(800, 600)

    def navigate_to_url(self):
        text = self.url_bar.text().strip()
        if not text:
            return
        
        # Wenn Text Leerzeichen enthält oder keine URL ist, als Suche behandeln
        if ' ' in text or not ('.' in text or text.startswith(('http://', 'https://'))):
            url = QUrl(f"https://duckduckgo.com/?q={text}")
        elif not text.startswith(('http://', 'https://')):
            url = QUrl(f"https://{text}")
        else:
            url = QUrl(text)
        
        # WEBSITE-SPERRUNG: Prüfung BEVOR Navigation startet
        if url.host() and is_site_blocked(url.host()):
            host = url.host().lower()
            self.statusBar().showMessage(f"🚫 Zugriff verweigert: {host} ist gesperrt", 5000)
            QMessageBox.warning(self, "Website gesperrt", 
                               f"Die Website '{host}' ist gesperrt und kann nicht aufgerufen werden.\n\n"
                               f"Verwenden Sie den roten Button zum Entsperren.")
            return
        
        current_tab = self.tabs.currentWidget()
        if current_tab:
            current_tab.setUrl(url)

    def close_tab(self, index):
        if self.tabs.count() > 1:
            widget = self.tabs.widget(index)
            self.tabs.removeTab(index)
            widget.deleteLater()
        else:
            # Letzten Tab nicht schließen, stattdessen DuckDuckGo laden
            current_tab = self.tabs.currentWidget()
            if current_tab:
                current_tab.setUrl(QUrl("https://duckduckgo.com"))
            # URL-Leiste aktualisieren
            self.url_bar.setText("https://duckduckgo.com")

    def update_url_bar(self):
        tab = self.tabs.currentWidget()
        if tab:
            url_string = tab.url().toString()
            # Leere URL-Leiste für die Startseite (Base64-URLs ausblenden)
            if url_string.startswith("data:") or not url_string or url_string == "about:blank":
                self.url_bar.setText("")
            else:
                self.url_bar.setText(url_string)

    def add_new_tab(self, url=None):
        tab = BrowserTab(self.tabs, self, self.profile, self.js_enabled)
        if url:
            tab.setUrl(QUrl(url))
        else:
            # Standardmäßig DuckDuckGo laden
            tab.setUrl(QUrl("https://duckduckgo.com"))
        # Tab-Titel dynamisch setzen
        title = "DuckDuckGo" if not url else "Neuer Tab"
        index = self.tabs.addTab(tab, title)
        self.tabs.setCurrentIndex(index)
        # Event-Handler
        tab.titleChanged.connect(lambda title, idx=index: self.update_tab_title(idx, title))
        tab.urlChanged.connect(self.update_url_bar)
        tab.loadStarted.connect(lambda idx=index: self.tabs.setTabText(idx, "Lade..."))
        tab.loadFinished.connect(lambda ok, idx=index: self.on_load_finished(idx, ok))
        # Link-Hover auch für den Tab selbst aktivieren (falls Page-Signal nicht funktioniert)
        tab.page().linkHovered.connect(self.on_link_hovered)
        
        # Website-Farben Inversion anwenden falls aktiviert
        if self.website_colors_inverted:
            # Kurze Verzögerung damit die Seite geladen ist
            QTimer.singleShot(500, lambda: self.apply_website_inversion_to_tab(tab))
        
        return tab



    def on_link_hovered(self, url):
        """Zeigt Link-URL in der Statusleiste beim Hover"""
        if url:
            self.statusBar().showMessage(f"🔗 {url}", 0)
        else:
            self.statusBar().clearMessage()

    def update_tab_title(self, index, title):
        if index < self.tabs.count() and title:
            short_title = title[:25] + "..." if len(title) > 25 else title
            self.tabs.setTabText(index, short_title)

    def on_load_finished(self, index, success):
        if index < self.tabs.count():
            tab = self.tabs.widget(index)
            if tab:
                title = tab.title() or tab.url().toString()
                self.update_tab_title(index, title)
                # Status-Update nach dem Laden
                if success:
                    self.statusBar().showMessage("Seite geladen", 2000)
                    # Website-Farben Inversion anwenden falls aktiviert
                    if self.website_colors_inverted:
                        QTimer.singleShot(100, lambda: self.apply_website_inversion_to_tab(tab))
                else:
                    self.statusBar().showMessage("Fehler beim Laden der Seite", 3000)

    def closeEvent(self, event):
        """Speichert alle Einstellungen beim Schließen des Browsers"""
        self.save_config()
        event.accept()

# -------- main --------
def main():
    # 0. Minimale GPU-Anpassungen: Nur Skia-SharedImage-Fehler beheben, Performance beibehalten
    # Sicherheitshinweis: --no-sandbox wurde entfernt (Sicherheitsrisiko)
    
    # 1. ZUERST: view-source registrieren (vor QApplication!)
    register_view_source()

    # 2. QApplication erstellen
    app = QApplication(sys.argv)
    
    # Windows-spezifische Einstellungen um versteckte Fenster zu vermeiden
    if sys.platform == "win32":
        app.setQuitOnLastWindowClosed(True)
    # Modernes Stylesheet aus surfwolf74.py
    app.setStyleSheet("""
    QWidget {
        font-family: 'Segoe UI', 'Arial', sans-serif;
        background: #f8f9fa;
    }
    QToolBar {
        background: qlineargradient(
            x1:0, y1:0, x2:1, y2:0,
            stop:0 #e3f0ff,
            stop:1 #caff70
        );
        border: 1px solid #e0e0e0;
        border-radius: 12px;
        margin: 8px;
        padding: 8px 16px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.07);
    }
    QPushButton {
        font-size: 18px;
        border-radius: 20px;
        background: #f5f5f5;
        color: #007bff;
        border: 1.5px solid #e0e0e0;
        padding: 8px;
    }
    QPushButton:hover {
        background: #e3e9f6;
        color: #0056b3;
        border: 1.5px solid #007bff;
    }
    QPushButton:pressed {
        background: #d0d7e6;
        color: #003087;
        border: 1.5px solid #003087;
    }
    QLineEdit {
        padding: 8px 16px 8px 36px;
        border-radius: 18px;
        font-size: 16px;
        background: #fff;
        color: #222;
        border: 1.5px solid #e0e0e0;
        margin: 0 8px;
    }
    QLineEdit:focus {
        background: #f8f9fa;
        border: 1.5px solid #007bff;
    }
    QMenu {
        font-size: 14px;
        padding: 5px;
        background: #fff;
        color: #222;
        border: 1px solid #e0e0e0;
        border-radius: 10px;
    }
    QMenu::item {
        padding: 7px 20px;
        border-radius: 8px;
    }
    QMenu::item:selected {
        background-color: #007bff;
        color: #fff;
    }
    QTabWidget::pane {
        border: none;
    }
    QTabBar::tab {
        font-size: 15px;
        padding: 10px 24px;
        margin-right: 4px;
        border-radius: 12px 12px 0 0;
        background: #e9ecef;
        color: #333;
        min-width: 80px;
    }
    QTabBar::tab:selected {
        background: #fff;
        color: #007bff;
        border-bottom: 3px solid #007bff;
    }
    QTabBar::tab:!selected:hover {
        background: #f1f3f7;
        color: #0056b3;
    }
    QTabBar::close-button {
        width: 18px;
        height: 18px;
        margin: 2px;
        background: #e9ecef;
        border-radius: 9px;
    }
    QTabBar::close-button:hover {
        background: #ff4d4d;
    }
    QStatusBar {
        font-size: 14px;
        padding: 5px;
        background: #f5f5f5;
        color: #333;
        border-top: 1px solid #e0e0e0;
    }
    """)
    
    # Icon setzen falls vorhanden
    if os.path.exists(ICON_PATH):
        app.setWindowIcon(QIcon(ICON_PATH))

    # 3. Hauptfenster erstellen (zunächst versteckt, Tab wird sofort erstellt)
    window = BrowserWindow()
    window.hide()  # Zunächst verstecken
    
    # 4. Fenster nach optimaler Zeit anzeigen (Event-Loop + WebEngine bereit)
    def show_window_when_ready():
        window.showMaximized()
    
    # Optimal Timer - Event Loop durchlaufen lassen + WebEngine stabilisieren
    QTimer.singleShot(50, show_window_when_ready)

    # 5. Event Loop starten
    sys.exit(app.exec())


if __name__ == '__main__':
    main()