# xpars

GET tabanlı reflected ve DOM XSS tarayıcı. xss0r'un gözlemlenen davranışından
(Anka ile analiz) türetilmiş clean-room, özgün bir Python uygulamasıdır. Orijinalin
kodu, payload veritabanı veya markası kopyalanmaz.

Yalnızca sahip olduğun ya da yazılı yetkin olan hedeflerde kullanılır.

## Kurulum

```
pip install -e .
```

## Kullanım

```
python -m xpars --get -u "http://host/path?p=1"
python -m xpars --get --urls hedefler.txt --payloads payloads.txt -o rapor.json
python -m xpars -u example.com --crawl
python -m xpars -u example.com --crawl 2 --max-pages 100
```

İki giriş biçimi var: parametreli URL (ya da `--urls` listesi) doğrudan test edilir;
ya da bir domain verip `--auto` ile xpars pasif toplama (Wayback) + crawl (link, GET/POST
form, inline JS, harici .js, robots/sitemap) + temizlik + tarama yapar.

Ek bayraklar: `--proxy http://127.0.0.1:8080` (Burp'e yönlendir), `--data "q=1&r=2"`
(POST gövdesi test et), `--json` (`--data` alanlarını JSON gövdesi olarak gönder),
`--header-scan` (Referer/User-Agent/X-Forwarded-For/Origin/cookie yansımasını test et),
`--path-scan` (URL yol segmentlerine enjekte et: /urun/BURAYA),
`--stored` (kalıcı/second-order XSS: enjekte et, sonra taranan sayfalarda ara),
`--rps N` (host başına saniyede en çok N istek; nazik tarama),
`--multipart` (POST formlarını multipart/form-data gönder; WAF/parsing atlatma),
`--json-data '{...}'` (iç içe JSON gövde şablonu; tüm string yaprakları tek tek test edilir),
`--blind-url URL` + `--blind-listen HOST:PORT` + `--blind-wait SN` (kör XSS OOB),
`--graphql-query 'Q'` + `--graphql-vars '{...}'` + `--graphql-url URL` (GraphQL
gövdesi: `variables` alanları ve gerekirse `query` enjekte edilir),
`--csti` (istemci-taraflı template enjeksiyonu: Angular/Vue `{{expr}}` degerlendirmesi),
`--evade` (WAF/filtre varken payload'ları encoding varyasyonlarıyla cogalt),
`--fail-on-finding` (bulgu varsa cikis kodu 3; CI icin), `--subdomains`,
`--endpoints uclar.txt` (tam uç listesini kaydet), `--aggressive-dedup`, `--no-dedup`.
GET formu, POST formu ve JSON gövdeli uçlar otomatik test edilir.

Tespit çekirdeği:
- Bir parametre birden çok yerde (ör. hem `<title>` hem gövde) yansıyabilir; xpars tüm
  yansımaları toplar ve en sömürülebilir bağlamı seçer, hiçbirini kaçırmaz. Bağlamlar:
  html, attribute (tırnaklı/tırnaksız), script, rcdata, style, comment, **uri** (href/src
  gibi URI attribute, `javascript:`), json, encoded.
- **Karakter hayatta kalma haritası**: her probe'ta `< > ' " ` + "`" + ` ( ) ; / { } = \` karakterlerinin
  hangisinin ham geçtiği, hangisinin entity'ye çevrildiği ölçülür (`ham-kar` alanı). Payload
  seçimini ve bypass kararını bu bilgi yönlendirir.
- **İskelet eşleşmesi**: payload birebir yansımasa da (boşluk esnetme, kısmi dönüşüm) tag +
  event-handler imzası ham olarak bir arada görünüyorsa "çalıştı" sayılır; escape edilmiş
  `&lt;` ve sayfanın kendi tag'leri yanlış pozitif üretmez.

Giriş noktaları (hiçbir yüzey kaçmasın):
- URL query parametreleri, **yol segmentleri** (`--path-scan`), GET/POST formları,
  **düz ve iç içe JSON gövde alanları** (`--json`, `--json-data`), **multipart form alanları**
  (`--multipart`), **GraphQL `variables`/`query` alanları** (`--graphql-query`),
  **HTTP header** ve **cookie** değerleri (`--header-scan`).
- **İstemci-taraflı template enjeksiyonu** (`--csti`): query parametresine benzersiz bir
  aritmetik ifade (`{{1337*1337}}`, `${1331*1333}`) enjekte eder; sonuç (1787569) ham
  ifade yerine yansıyorsa template motoru girdiyi degerlendirmiş demektir (Angular/Vue
  gibi) ve CSTI raporlanır. Yalnizca degerlendirme olunca tetikler, duz yansima FP uretmez.
- **Kalıcı yüzey** (`--stored`): bir forma ya da parametreye enjekte edilen işaretli payload,
  taranan diğer sayfalarda ham olarak geri geliyorsa stored/second-order XSS raporlanır.
- **Kör (blind) XSS** (`--blind-url`/`--blind-listen`): tüm yüzeylere işaretli bir beacon
  (`<script src=callback/MARKER>`) enjekte eder; yerleşik HTTP toplayıcı geri-aramayı yakalayınca
  MARKER sayesinde hangi noktanın tetiklendiğini raporlar. Admin panelleri gibi gecikmeli
  tetiklenen noktalar için `--blind-wait` ile toplayıcı açık tutulur.

Üst düzey yetenekler:
- `--verify`: bulunan XSS'leri gerçek headless tarayıcıda (Playwright/Chromium) açıp
  alert/dialog'un gerçekten tetiklendiğini doğrular. Doğrulanan bulgu `critical` olur
  ve `execution` damgası alır. Payloadsız sayfa zaten dialog açıyorsa (sayfanın kendi
  JS'i) bu baz çizgisi olarak işaretlenir ve yanlış pozitif sayılmaz. Playwright kurulu
  değilse zarifçe atlanır (`pip install playwright && python -m playwright install chromium`).
  Doğrulama tüm yöntemleri kapsar: GET (query/path), POST (otomatik gönderilen form),
  POST-JSON ve **GraphQL** (fetch + document.write; GraphQL yalnızca yanıt text/html
  bağlamındaysa execution doğrulanır, saf JSON yanıt dürüstçe reflected kalır), özel HTTP
  header, cookie ve **User-Agent** (ayrı tarayıcı context'i ile). **Referer ve Origin**
  tarayıcı tarafından sanitize edildiği için enjekte edilip tespit edilir ama tarayıcıda
  execution doğrulanamaz; bu bulgular `browser-controlled-header` notuyla aday kalır.
  **DOM** adayları kaynak sınıfına göre tetiklenir:
  `location.hash`/`href` (fragment), `location.search` (query), `window.name` ve `postMessage`;
  sink JS çalıştırıyorsa (eval/Function) `alert(1)`, markup ise `<img onerror>` denenir.
  **Stored** bulgular hedef sayfa açılarak doğrulanır. Gerçekten tetiklenen bulgu `critical`
  olur; tetiklenmeyen aday statik kalır (yanlış pozitif üretmez).
- `--html rapor.html`: tek dosya, bağımsız HTML rapor (severity rozetleri, WAF/CSP özeti,
  DOM kaynak/sink tablosu, her bulgu için kopyala-çalıştır `curl` PoC).
- CSP farkındalığı: yanıtın `Content-Security-Policy` başlığı okunur; inline script'i
  engelleyen bir politika varsa bulguya not düşülür (execution için `--verify` ile teyit).
- Her bulgu hazır bir `curl` PoC ile raporlanır (GET/POST/JSON/header/cookie'ye göre).
- `--insecure`: TLS doğrulamasını atla (kendinden imzalı sertifikalı laboratuvarlar).
- Çıktı JSON (`-o`), metin (severity sıralı) ve HTML birlikte üretilebilir.
- `--log dosya`: gönderilen her istek anında (flush'lı) log dosyasına yazılır; tarama
  yarıda kesilse bile kanıt kalır. `-v/--verbose` aynısını stderr'e basar.
- `--detect [dosya]`: bir bulgu çıktığı an tek satır olarak detect dosyasına eklenir
  (varsayılan `detect.txt`, append + tekilleştirme). JSON/HTML rapor bitmeyi beklerken
  bulgular canlı birikir; uzun taramada ve süreç ölse de bulgu listesi elde kalır.
- Dayanıklılık: yanıt gövdesi 3 MB'a kadar okunur (OOM koruması), 429'da Retry-After
  ile üstel bekleme, hata yalıtımı, bulgu tekilleştirme, her bulguda severity/how alanı.

Genişletilmiş yetenekler:
- `--full-payloads`: xss0r davranış analizinden türetilmiş genişletilmiş payload
  havuzu (`xpars/data/payloads_full.txt`, ~4500 vektör, marka izleri temizlenmiş).
  Kapsamlı ama yavaş; hedef başına çok istek atar. İnce tarama için `--payloads`
  ile kendi listeni ver.
- `--crlf`: CRLF/header-injection -> XSS denemesi (header split, Set-Cookie, gövde ayırma).
- `--brute-params`: parametresiz uçlara yaygın parametre adlarını (q, id, url, redirect...)
  körlemesine ekler. Hızlı ama kaba; gerçek keşif için aşağıdaki `--discover`.
- `--discover`: Arjun tarzı anomali tabanlı gizli parametre keşfi. Önce hedefe birkaç
  rastgele istekle kararlı bir yanıt parmak izi (durum kodu, başlık kümesi, uzunluk,
  satır/kelime sayısı, yönlendirme) çıkarır ve her istekte kendiliğinden değişen
  faktörleri atar (yanlış pozitif koruması). Sayfa girdisini aynen yansıtıyorsa
  yansıma sinyali ve boyut faktörleri devre dışı bırakılır. Sonra sözlüğü öbeklere
  bölüp her öbeği tek istekte dener, anomali veren öbeği ikili arama ile tekil
  parametreye kadar daraltır; her aday ikinci bir istekle doğrulanır. Böylece binlerce
  ad az sayıda istekle taranır. Bulunan gizli parametreler doğrudan XSS motoruna
  (bağlam tespiti -> payload -> tarayıcı doğrulama) beslenir.
  - `--discover-full`: gömülü geniş sözlük (`xpars/data/params.txt`, ~360 ad).
  - `--param-wordlist dosya.txt`: kendi parametre sözlüğün (SecLists gibi).
  - `--discover-chunk N`: başlangıç öbek boyu (GET'te URL uzunluğuna göre otomatik kısılır).
  - `--discover-method GET|POST`: keşif isteğinin yöntemi (POST gövdede dener).
  - `--discover-endpoints N`: kaç ayrı uçta keşif yapılacağı (yol başına tekilleştirilir).
- `--passive`: pasif URL toplama (Wayback/urlscan/OTX). Ayrı bir bayraktır; `--auto`
  artık yalnızca crawl yapar, pasif için `--passive` eklenir.
  - `--passive-sources wayback,urlscan,otx,crtsh,hackertarget`: kaynak seçimi.
    Varsayılan wayback + urlscan + otx; `--subdomains` ile crt.sh ve hackertarget
    eklenir (hepsi anahtarsız).
- WAF/CDN parmak izi her host icin otomatik calisir (Cloudflare, Akamai, Imperva, Sucuri,
  PerimeterX, F5, Barracuda, CloudFront, DataDome...). `--no-waf` ile kapatilir.
- `--stop-on-confirm`: bir host doğrulanınca o host için kalan hedefleri atla (varsayılan
  KAPALI; tam kapsam korunur).

Bayraklar xss0r ile hizalı: `--get`, `--urls`, `--payloads`, `--shuffle`, `--clear`,
`-t/--threads`, `--delay`, `--timeout`, `--blind`, `-H/--header`, `--cookie`,
`--user-agent`, `--scope`, `--exclude`, `-o/--output`.

## Güvenlik

- `--scope` allowlist, `--exclude` denylist. `europa.eu` ve `unesco.org` varsayılan
  olarak reddedilir.

## Ne yapar

- Gizli/görünmeyen parametreleri anomali tabanlı keşifle bulur (`--discover`) ve
  bulunan parametreleri doğrudan XSS testine taşır; böylece sadece görünen değil
  görünmeyen saldırı yüzeyi de taranır.
- URL query, yol segmenti, form, düz ve iç içe JSON gövde, multipart, GraphQL
  (`variables`/`query`), header ve cookie noktalarına benzersiz işaretçili prob enjekte
  eder, tüm yansımaları bulup bağlamı (html, attribute, script, rcdata, style, comment,
  uri, json, encoded) sınıflandırır.
- İstemci-taraflı template enjeksiyonunu (`--csti`) aritmetik-degerlendirme sondasıyla
  tespit eder; duz yansimayi CSTI sanmaz (yanlis pozitif uretmez).
- Kalıcı yüzeylere (`--stored`) enjeksiyon sonrası taranan sayfa korpusunda ham landing
  arar; bulursa stored/second-order XSS olarak işaretler.
- Kör XSS için (`--blind-url`/`--blind-listen`) her yüzeye işaretli beacon enjekte eder ve
  yerleşik toplayıcıyla hangi noktadan geri-arama geldiğini eşler.
- Hem satır içi script'lerde hem **harici .js dosyalarında** DOM kaynak/sink eşleşmesini
  (location.hash/search/referrer, **window.name**, **postMessage/onmessage** -> innerHTML/
  eval/document.write/jQuery gibi) tespit eder. DOM taraması host+path ve script-URL başına
  tekilleştirilir (nazik); hash tabanlı sink'ler için hazır payload ve PoC URL'si üretir.
- `--auto`/`--crawl` modunda DOM taraması, `--header-scan` ve `--path-scan` artık yalnızca
  parametreli hedefleri değil **keşfedilen tüm uçları** kapsar. Böylece parametresiz DOM-XSS
  sayfaları ve header/path yüzeyleri (ör. parametresiz bir panel) kaçmaz. Daha fazla istek
  atar; `--rps` ve `--max-pages` ile sınırlanabilir.
- JSON yanıt gövdesindeki yansımalar (`application/json`) `medium` olarak işaretlenir (saf
  JSON API genelde çalıştırılamaz); `<script type="application/json">` gibi veri blokları
  çalıştırılabilir script sanılmaz, yalnızca gerçek `</script>` breakout'u varsa bulgu üretir.
- Çok iş parçacıklı; gecikme, 429 ve 5xx yönetimli; metin, JSON ve HTML çıktılı.
