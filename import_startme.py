import os
import json
import re

# The JSON data extracted from start.me
WIDGETS_DATA = [
  {
    "widgetTitle": "Forensic Blog Feed",
    "bookmarks": []
  },
  {
    "widgetTitle": "Phishing Email/Suspicious URL",
    "bookmarks": [
      { "title": "phishtool-Auto analyze emails", "url": "https://app.phishtool.com/" },
      { "title": "Email Header Analyzer Tool To Find Spam", "url": "https://www.whatismyip.com/email-header-analyzer/" },
      { "title": "Email Header Analyzer, RFC822 Parser", "url": "https://mxtoolbox.com/EmailHeaders.aspx" },
      { "title": "Complete email header analysis. Analyse, track ip here", "url": "https://www.iptrackeronline.com/email-header-analysis.php" },
      { "title": "Email Verification Tools-Twitter Thread", "url": "https://twitter.com/hacktoria/status/1575737778628952069" },
      { "title": "Email Analyzer (T)", "url": "https://github.com/keraattin/EmailAnalyzer" },
      { "title": "urlscan.io-URL and website scanner", "url": "https://urlscan.io/" },
      { "title": "domain reputation: URL/IP Lookup", "url": "https://www.brightcloud.com/tools/url-ip-lookup.php" },
      { "title": "ScanMySMS", "url": "https://www.scanmysms.com/en" },
      { "title": "Konfidas Whatsapp bot", "url": "https://wa.me/97236444417?text=4" },
      { "title": "Interactive Online Malware Analysis Sandbox", "url": "https://app.any.run/" },
      { "title": "Google Transparency Report", "url": "https://transparencyreport.google.com/safe-browsing/search" },
      { "title": "ScanURL.net", "url": "https://scanurl.net/" },
      { "title": "virtual sandboxed browser-Browserling", "url": "https://www.browserling.com/" },
      { "title": "Is This Website Safe", "url": "https://safeweb.norton.com/" },
      { "title": "PhishTank", "url": "https://www.phishtank.com/" },
      { "title": "VirusTotal", "url": "https://www.virustotal.com/gui/home/upload" },
      { "title": "DFNDR Lab", "url": "https://www.psafe.com/dfndr-lab/" },
      { "title": "URLVoid", "url": "https://www.urlvoid.com/" },
      { "title": "site check sucuri", "url": "https://sitecheck.sucuri.net/" },
      { "title": "Scan url link Check for Phishing, Malware, Viruses, blacklist", "url": "https://www.scanurl.me/?lang=en" },
      { "title": "Zscaler", "url": "https://zulu.zscaler.com/" },
      { "title": "urlquery.net", "url": "https://urlquery.net/" },
      { "title": "Malicious URL Scanner", "url": "https://www.ipqualityscore.com/threat-feeds/malicious-url-scanner" },
      { "title": "Phishing URL Checker", "url": "https://easydmarc.com/tools/phishing-url" },
      { "title": "Validin", "url": "https://app.validin.com/detail" },
      { "title": "Hunting.abuse.ch", "url": "https://hunting.abuse.ch/" }
    ]
  },
  {
    "widgetTitle": "Phising/Malware Analysis",
    "bookmarks": [
      { "title": "Phising Playbook", "url": "https://board.flexibleir.com/b/vDy7w4wNwJTxUi53i/1" },
      { "title": "The phishing response playbook - Infosec Resources", "url": "https://resources.infosecinstitute.com/topic/the-phishing-response-playbook/" },
      { "title": "EasyThreatFile Tool", "url": "https://s0cm0nkey.github.io/EasyThreatFile.html" },
      { "title": "EchoTrail Process Database Search", "url": "https://www.echotrail.io/insights" }
    ]
  },
  {
    "widgetTitle": "Threat Hunting",
    "bookmarks": [
      { "title": "ThreatMiner", "url": "https://www.threatminer.org/" },
      { "title": "VirusTotal", "url": "https://www.virustotal.com/" },
      { "title": "AlienVault", "url": "https://otx.alienvault.com/preview" },
      { "title": " RansomLook ", "url": "https://www.ransomlook.io/" },
      { "title": "MISP Search", "url": "https://search.misp-community.org/" },
      { "title": "APT Groups and Operations", "url": "https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit?gid=1864660085#gid=1864660085" },
      { "title": "Google APT Groups CSE", "url": "https://cse.google.com/cse?cx=003248445720253387346:turlh5vi4xc" },
      { "title": "ransomwatch", "url": "https://ransomwatch.telemetry.ltd/#/" },
      { "title": "Ransomware.live", "url": "https://ransomware.live/map/IL" },
      { "title": "Crowdstrike Falcon Threat landscape", "url": "https://falcon.crowdstrike.com/intelligence-v2/threat-landscape" },
      { "title": "Kaspersky Threat Intelligence Portal", "url": "https://opentip.kaspersky.com/" },
      { "title": "StealthMole", "url": "https://platform.stealthmole.com/cases/31a2db79-2106-11f0-a031-3cecefdf4a0c" }
    ]
  },
  {
    "widgetTitle": "Hashes to Hashes",
    "bookmarks": [
      { "title": "Hashes", "url": "https://hashes.com/en/decrypt/hash" },
      { "title": "CrackStation", "url": "https://crackstation.net/" },
      { "title": "CyberChef", "url": "https://gchq.github.io/CyberChef/" }
    ]
  },
  {
    "widgetTitle": "Malware Related",
    "bookmarks": [
      { "title": "VirusTotal", "url": "https://www.virustotal.com/gui/home/upload" },
      { "title": "Polyswarm.network-Scan files for threats", "url": "https://polyswarm.network/" },
      { "title": "Reverss-Malware Dashboard", "url": "https://sandbox.anlyz.io/dashboard" },
      { "title": "Search hash - Jotti's malware scan", "url": "https://virusscan.jotti.org/en-US/search/hash#" },
      { "title": "MalwareBazaar-Sharing malware samples with the community", "url": "https://bazaar.abuse.ch/browse/" },
      { "title": "YARAify | YARA File Scan", "url": "https://yaraify.abuse.ch/scan/" },
      { "title": "malwares.com", "url": "https://www.malwares.com/" },
      { "title": "ThreatFox-Indicator Of Compromise (IOC) database", "url": "https://threatfox.abuse.ch/browse/" },
      { "title": "valkyrie comodo", "url": "https://valkyrie.comodo.com/" },
      { "title": "EasyThreat Tool", "url": "https://s0cm0nkey.github.io/EasyThreat.html" },
      { "title": "EasyThreatFile Tool", "url": "https://s0cm0nkey.github.io/EasyThreatFile.html" },
      { "title": "site check sucuri", "url": "https://sitecheck.sucuri.net/" }
    ]
  },
  {
    "widgetTitle": "Sandbox",
    "bookmarks": [
      { "title": "Falcon Sandbox", "url": "https://falcon.crowdstrike.com/intelligence/sandbox" },
      { "title": "Hatching Triage-Recorded Future Sandbox", "url": "https://tria.ge/" },
      { "title": "cuckoo", "url": "https://cuckoo.cert.ee/dashboard/" },
      { "title": "ANY.RUN", "url": "https://any.run/" },
      { "title": "Joe Sandbox", "url": "https://www.joesandbox.com/#windows" },
      { "title": "Opentip.kaspersky.com", "url": "https://opentip.kaspersky.com/#search/" }
    ]
  },
  {
    "widgetTitle": "Google/Shodan Dorks",
    "bookmarks": [
      { "title": "hidden files dork", "url": "https://github.com/0xAbbarhSF/Info-Sec-Dork-List/blob/main/hidden_files_dork.txt" },
      { "title": "Top 40 Shodan Dorks for Finding Sensitive IoT Data", "url": "https://securitytrails.com/blog/top-shodan-dorks" },
      { "title": "Dorks collections list", "url": "https://github.com/cipher387/Dorks-collections-list/" },
      { "title": "Top 7 #Shodan Dorks (Twitter Thread)", "url": "https://twitter.com/AseemShrey/status/1508059759491964928" },
      { "title": "awesom shodan queries", "url": "https://github.com/jakejarvis/awesome-shodan-queries" },
      { "title": "Google Hacking Database", "url": "https://www.exploit-db.com/google-hacking-database" },
      { "title": "Domain documents Dork", "url": "https://twitter.com/TakSec/status/1683175246801797120?s=09&t=zXvq-_nviPlMHAobDoXoqg" }
    ]
  },
  {
    "widgetTitle": "URL/IP Scan",
    "bookmarks": [
      { "title": "Vortimo OSINT Tool", "url": "https://osint-tool.com/" },
      { "title": "VirusTotal", "url": "https://www.virustotal.com/gui/home/search" },
      { "title": "URL and website scanner", "url": "https://urlscan.io/" },
      { "title": "URL Content Dump, Web Sniffer | Toolsvoid", "url": "https://www.toolsvoid.com/url-dump/" },
      { "title": "Web-check.xyz", "url": "https://web-check.xyz/" },
      { "title": "AbuseIPDB", "url": "https://www.abuseipdb.com/" },
      { "title": "IPQualityScore", "url": "https://www.ipqualityscore.com/" },
      { "title": "Cisco Talos Intelligence Group", "url": "https://www.talosintelligence.com/" },
      { "title": "IPInfo", "url": "https://ipinfo.io/" },
      { "title": "Checkphish.ai", "url": "https://checkphish.ai/" },
      { "title": "WHOIS information", "url": "https://centralops.net/co/" },
      { "title": "IBM X-Force Exchange", "url": "https://exchange.xforce.ibmcloud.com/" },
      { "title": "Opswat-meta defender Cloud", "url": "https://metadefender.opswat.com/" },
      { "title": "ThreatMiner", "url": "https://www.threatminer.org/" },
      { "title": "Criminal IP", "url": "https://www.criminalip.io/" },
      { "title": "Cybercrime-tracker.net", "url": "http://cybercrime-tracker.net/" },
      { "title": "Phishtank.org", "url": "https://phishtank.org/" },
      { "title": "OpenPhish", "url": "https://openphish.com/index.html" },
      { "title": "Ransomware.live", "url": "https://www.ransomware.live/#/" },
      { "title": "Google Safe Browsing", "url": "https://transparencyreport.google.com/safe-browsing/search?hl=en" },
      { "title": "URLVoid", "url": "https://www.urlvoid.com/" },
      { "title": "Scanurl.me", "url": "https://www.scanurl.me/?lang=en" },
      { "title": "urlquery.net", "url": "https://urlquery.net/" },
      { "title": "Zscaler", "url": "https://zulu.zscaler.com/" },
      { "title": "blocklist.de", "url": "http://www.blocklist.de/en/search.html" },
      { "title": "EasyThreat Tool", "url": "https://s0cm0nkey.github.io/EasyThreat.html" },
      { "title": "Free Website Scam Checker", "url": "https://www.getsafeonline.org/checkawebsite/" },
      { "title": "ScamAlert", "url": "https://www.scamalert.sg/" },
      { "title": "Scamadviser", "url": "https://www.scamadviser.com/" },
      { "title": "AlienVault Open Threat Exchange", "url": "https://otx.alienvault.com/" },
      { "title": "Hatching Triage", "url": "https://tria.ge/" },
      { "title": "IoC IP and Domain Name Tool", "url": "https://threatstop.com/checkip" },
      { "title": "Is It Phishing (IP,domain,brand, host)", "url": "https://isitphishing.org/" },
      { "title": "Joe Sandbox URL Analyzer", "url": "https://www.url-analyzer.net/" },
      { "title": "Sucuri Site Check", "url": "https://sitecheck.sucuri.net/" },
      { "title": "MX Toolbox SuperTool", "url": "https://mxtoolbox.com/SuperTool.aspx" },
      { "title": "SecurityTrails", "url": "https://securitytrails.com/#search" },
      { "title": "Webroot Brightcloud URL Lookup", "url": "https://www.brightcloud.com/tools/url-ip-lookup.php" },
      { "title": "Private PI-Hole Blocked search", "url": "http://10.0.0.162/admin/queryads.php" },
      { "title": "IntelOwl", "url": "http://20.123.9.203/dashboard" },
      { "title": "MISP", "url": "https://tenroot-misp.northeurope.cloudapp.azure.com/" },
      { "title": "GreyNoise Visualizer", "url": "https://viz.greynoise.io/" },
      { "title": "ShadowCrypt", "url": "https://shadowcrypt.net/" },
      { "title": "ThreatBook TI", "url": "https://threatbook.io/" }
    ]
  },
  {
    "widgetTitle": "Social Serch",
    "bookmarks": [
      { "title": "waybien-search telegram/facebook/whatsapp", "url": "https://waybien.com/en" },
      { "title": "Telegago", "url": "https://cse.google.com/cse?&cx=006368593537057042503:efxu7xprihg#gsc.tab=0" },
      { "title": "Social Searcher", "url": "https://www.social-searcher.com/" }
    ]
  },
  {
    "widgetTitle": "Courses",
    "bookmarks": [
      { "title": "site:drive.google.com course name", "url": "https://www.google.com/search?q=site%3Adrive.google.com+powershell" },
      { "title": "100 courses links", "url": "https://drive.google.com/file/d/1BOAj0_VUYxuj6Se76EHPKhudPsNSf5HZ/view?usp=drivesdk" },
      { "title": "Index of /pilhadosaber/", "url": "https://www.kgay4all.com/seioqueseiporleroqueleio/" },
      { "title": "https://www.coursedl.org/0:/", "url": "https://www.coursedl.org/0:/" },
      { "title": "Eyedex.org-open directories search", "url": "https://www.eyedex.org/" },
      { "title": "Filepursuit.com", "url": "https://filepursuit.com/" },
      { "title": "Odcrawler.xyz", "url": "https://odcrawler.xyz/" },
      { "title": "Open Directory Search Tool · Abifog", "url": "https://opendirsearch.abifog.com/" },
      { "title": "serbianforum", "url": "https://serbianforum.org/forums/video-tutorijali.341/" },
      { "title": "Tutorials & Training For IT", "url": "https://tut4it.com/" },
      { "title": "Tut4Sec - OS & Server , Security Training", "url": "https://tut4sec.com/" },
      { "title": "cybersecurityleaks", "url": "https://cybersecurityleaks.com/home" }
    ]
  },
  {
    "widgetTitle": "OSINT Frameworks",
    "bookmarks": [
      { "title": "My OSINT Mindmap", "url": "https://whimsical.com/osint-NxduuyaZtgi29RLwyPGMnH" },
      { "title": "OSINT Framework", "url": "https://osintframework.com/" },
      { "title": "OSINT Toolkit", "url": "https://one-plus.github.io/access.html" },
      { "title": "inteltechniques Private Tools", "url": "https://inteltechniques.com/osintnet/tools/" },
      { "title": "IntelTechniques OSINT Online Search Tool", "url": "https://inteltechniques.com/tools/index.html" },
      { "title": "Bellingcat's Online Investigation Toolkit", "url": "https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/edit#gid=930747607" },
      { "title": "OSINT for Finding People", "url": "https://docs.google.com/spreadsheets/d/1JxBbMt4JvGr--G0Pkl3jP9VDTBunR2uD3_faZXDvhxc/edit#gid=1978517898" },
      { "title": "CTI & OSINT Online Resources", "url": "https://docs.google.com/spreadsheets/d/1klugQqw6POlBtuzon8S0b18-gpsDwX-5OYRrB7TyNEw/edit#gid=0" },
      { "title": "Aware Online OSINT Tools", "url": "https://www.aware-online.com/en/osint-tools/" },
      { "title": "intel Techniques OSINT_Team_Links", "url": "https://github.com/IVMachiavelli/OSINT_Team_Links" },
      { "title": "PWF DFIR CheatSheet", "url": "https://github.com/bluecapesecurity/PWF/blob/main/Resources/PracticalWindowsForensics-cheat-sheet.pdf" },
      { "title": "DFIR Cheatsheet", "url": "https://www.jaiminton.com/cheatsheet/DFIR/#" },
      { "title": "Vortimo OSINT Tool", "url": "https://osint-tool.com/" },
      { "title": "Bellingcat’s Online Open Source Investigation Toolkit!", "url": "https://bellingcat.gitbook.io/toolkit" },
      { "title": "Offensive Security Cheatsheet", "url": "https://cheatsheet.haax.fr/open-source-intelligence-osint/?s=09" },
      { "title": "MetaOSINT.github.io", "url": "https://metaosint.github.io/" },
      { "title": "OSINT Tools", "url": "https://www.osinttechniques.com/osint-tools.html" },
      { "title": "OSINT Investigation Assistant", "url": "https://lambda.black/osint.html" },
      { "title": "Osint.link", "url": "https://osint.link/" },
      { "title": "OSINT Map (OSINT Framework Alternative)", "url": "https://map.malfrats.industries/" },
      { "title": "Cyber Detective Osint Collection", "url": "https://github.com/cipher387/osint_stuff_tool_collection" },
      { "title": "Hushint", "url": "https://www.hushint.com/osint/index.php" },
      { "title": "OSINT in 2022. Full catalogue of tools", "url": "https://www.advisor-bm.com/osint-tools" },
      { "title": "OSINT METHODOLOGY & Flowcharts", "url": "https://cheatsheet.haax.fr/open-source-intelligence-osint/tools-and-methodology/methodology/" },
      { "title": "OSINT Toolkit", "url": "https://www.andyblackassociates.co.uk/resources-andy-black-associates/osint-toolkit/" },
      { "title": "OsintCombine.com Free Tools", "url": "https://www.osintcombine.com/tools" },
      { "title": "OSINT diagrams for attack surface", "url": "https://github.com/sinwindie/OSINT" },
      { "title": "Ph055a/OSINT_Collection", "url": "https://github.com/Ph055a/OSINT_Collection/blob/master/README.md" },
      { "title": "Awesome Hacker Search Engines", "url": "https://github.com/edoardottt/awesome-hacker-search-engines" },
      { "title": "Security Search Engines", "url": "https://github.com/Nguyen-Trung-Kien/Security-Search-Engines/blob/1bda895d343e3c8cab27252b3b7f7f3c90257671/README.md" },
      { "title": "Email-Username-OSINT-ManuelBOT.xlsx", "url": "https://docs.google.com/spreadsheets/d/1vf91U__HvlNuBkY8T12CLu34AYgEbcbk/edit#gid=183866541" },
      { "title": "Cylect.io", "url": "https://cylect.io/" },
      { "title": "GeoHints-Geolocation Identification", "url": "https://geohints.com/" },
      { "title": "Welcome to OSINT Tools Directory", "url": "https://osinttools.io/free/" },
      { "title": "SynapsInt", "url": "https://synapsint.com/" },
      { "title": "OPEN SOURCE INTELLIGENCE NEW ZEALAND", "url": "https://osint.rocks/" },
      { "title": "Osint one liners", "url": "https://github.com/yogsec/One-Liner-OSINT" },
      { "title": "The OSINT Rack – Mario Santella", "url": "https://www.mariosantella.com/the-osint-rack/" },
      { "title": "Cignalosint.lovable.app", "url": "https://cignalosint.lovable.app/" },
      { "title": "SOC Toolkit", "url": "https://soctoolkit.com/" }
    ]
  },
  {
    "widgetTitle": "Username OSINT",
    "bookmarks": [
      { "title": "IntelTechniques Username Search Tool", "url": "https://inteltechniques.com/tools/Username.html" },
      { "title": "OSINT Toolkit Username Misc Tools", "url": "https://one-plus.github.io/EmailUsername" },
      { "title": "intelx Username", "url": "https://intelx.io/tools?tab=username" },
      { "title": "Telegram Multi Search", "url": "https://web.telegram.org/k/#@UniversalSearchRobot" },
      { "title": "OPEN SOURCE INTELLIGENCE NEW ZEALAND", "url": "https://osint.rocks/" },
      { "title": "Aware-Online Username search tool", "url": "https://www.aware-online.com/en/osint-tools/username-search-tool/" },
      { "title": "Aware-Online OSINT tools", "url": "https://www.aware-online.com/osint-tools/gebruikersnamen-tools/" },
      { "title": "Vortimo OSINT Tool", "url": "https://osint-tool.com/" },
      { "title": "Spokeo", "url": "https://www.spokeo.com/" },
      { "title": "NameCheckup", "url": "https://namecheckup.com/" },
      { "title": "WhatsMyName Web", "url": "https://whatsmyname.app/" },
      { "title": "Namechk", "url": "https://namechk.com/" },
      { "title": "Ufind.name", "url": "https://ufind.name/" },
      { "title": "Telegram Web", "url": "https://web.telegram.org/k/#@osint_maigret_bot" },
      { "title": "Instant Username Search", "url": "https://instantusername.com/#/" },
      { "title": "amazon user", "url": "https://www.google.com/search?q=site:amazon.com+%3Cusername%3E" },
      { "title": "Github User", "url": "https://api.github.com/users/%3Cusername%3E/events/public" },
      { "title": "Tinder user", "url": "https://tinder.com/@%3Cusername%3E" },
      { "title": "sherlock-project/sherlock", "url": "https://github.com/sherlock-project/sherlock" },
      { "title": "Leaks Database", "url": "https://search.ddosecrets.com/" }
    ]
  },
  {
    "widgetTitle": "Full Name OSINT",
    "bookmarks": [
      { "title": "inteltechniques Name search", "url": "https://inteltechniques.com/tools/Name.html" },
      { "title": "Aware-Online People search Tool", "url": "https://www.aware-online.com/en/osint-tools/people-search-tool/" },
      { "title": "Aware-Online OSINT tools for investigating people", "url": "https://www.aware-online.com/en/osint-tools/people-tools/" },
      { "title": "intelx Person", "url": "https://intelx.io/tools?tab=person" },
      { "title": "Thats them", "url": "https://thatsthem.com/" },
      { "title": "Vortimo OSINT Tool", "url": "https://osint-tool.com/" },
      { "title": "Spokeo", "url": "https://www.spokeo.com/" },
      { "title": "IDCrawl", "url": "https://www.idcrawl.com/" },
      { "title": "WebMii", "url": "https://webmii.com/" },
      { "title": "White Pages", "url": "https://www.whitepages.com/" },
      { "title": "Telegram Web", "url": "https://web.telegram.org/k/#@OsintKierAbusha_bot" }
    ]
  },
  {
    "widgetTitle": "Emails OSINT",
    "bookmarks": [
      { "title": "IntelTechniques Email Search Tool", "url": "https://inteltechniques.com/tools/Email.html" },
      { "title": "Aware-Online E-mail search tool", "url": "https://www.aware-online.com/osint-tools/e-mail-search-tool/" },
      { "title": "Aware-Online OSINT tools", "url": "https://www.aware-online.com/osint-tools/emailadressen-tools/" },
      { "title": "Osint.industries-search account used by an email", "url": "https://osint.industries/" },
      { "title": "osint.rocks", "url": "https://osint.rocks/" },
      { "title": "intelx Emails", "url": "https://intelx.io/tools?tab=email" },
      { "title": "Phonebook.cz (emails in breaches)", "url": "https://phonebook.cz/" },
      { "title": "Thats Them", "url": "https://thatsthem.com/reverse-email-lookup" },
      { "title": "Vortimo OSINT Tool", "url": "https://osint-tool.com/" },
      { "title": "Epieos", "url": "https://epieos.com/" },
      { "title": "Spokeo", "url": "https://www.spokeo.com/" },
      { "title": "Hunter", "url": "https://hunter.io/" },
      { "title": "VoilaNorbert", "url": "https://www.voilanorbert.com/" },
      { "title": "Whoxy-Reverse Domain Registration", "url": "https://www.whoxy.com/" },
      { "title": "Seon.io", "url": "https://seon.io/" },
      { "title": "Advanced Reverse Email Lookup API", "url": "https://enrich.so/" },
      { "title": "BreachDirectory", "url": "https://breachdirectory.org/" },
      { "title": "Email Finder • Free email search for B2B sales", "url": "https://snov.io/email-finder" },
      { "title": "Castrick", "url": "https://castrickclues.com/" },
      { "title": "Leakpeek.com", "url": "https://leakpeek.com/" },
      { "title": "Predicta Search", "url": "https://www.predictasearch.com/" },
      { "title": "Falcon.crowdstrike.com", "url": "https://falcon.crowdstrike.com/intelligence-v2/recon" },
      { "title": "Intelbase.is", "url": "https://intelbase.is/" }
    ]
  },
  {
    "widgetTitle": "Photos OSINT",
    "bookmarks": [
      { "title": "IntelTechniques Multi Images Search Tool", "url": "https://inteltechniques.com/tools/Images.html" },
      { "title": "intelx Photos", "url": "https://intelx.io/tools?tab=image" },
      { "title": "Google Image search", "url": "https://www.google.com/imghp" },
      { "title": "Reverse Image Search", "url": "https://www.reverse-image-search.com/" },
      { "title": "TinEye", "url": "https://tineye.com/" },
      { "title": "Yandex image search", "url": "https://yandex.com/images/?rpt=imageview" },
      { "title": "Bing image search", "url": "https://www.bing.com/images/feed" },
      { "title": "Baidu Image search", "url": "https://graph.baidu.com/pcpage/index?tpl_from=pc" },
      { "title": "Aware-Online OSINT tools for photos and videos", "url": "https://www.aware-online.com/en/osint-tools/photo-and-video-tools/" },
      { "title": "Facecheck.id", "url": "https://facecheck.id/?s=09" },
      { "title": "Reverse Image Search AI", "url": "https://www.numlookup.com/reverse-image-search" },
      { "title": "Lenso.ai", "url": "https://lenso.ai/en" },
      { "title": "GeoGuessr GPT", "url": "https://chatgpt.com/g/g-brlHi7t2R-geoguessr-gpt" },
      { "title": "Geolocation Estimation", "url": "https://labs.tib.eu/geoestimation/" },
      { "title": "Find Photo Location Using AI", "url": "https://picarta.ai/" },
      { "title": "EarthKit", "url": "https://earthkit.app/" },
      { "title": "Geospy.web.app", "url": "https://geospy.web.app/" }
    ]
  },
  {
    "widgetTitle": "Social Media OSINT",
    "bookmarks": [
      { "title": "Facebook: IntelTechniques Search Tool", "url": "https://inteltechniques.com/tools/Facebook.html" },
      { "title": "Facebook: Misc Tools", "url": "https://one-plus.github.io/Facebook" },
      { "title": "Facebook: Graph Searcher", "url": "https://intelx.io/tools?tab=facebook" },
      { "title": "Facebook: Search", "url": "https://www.sowsearch.info/" },
      { "title": "Facebook: email search", "url": "https://www.facebook.com/search/top/?q=email%40gmail.com" },
      { "title": "Facebook: Find my ID", "url": "https://lookup-id.com/" },
      { "title": "LinkedIn: IntelTechniques Search Tool", "url": "https://inteltechniques.com/tools/Linkedin.html" },
      { "title": "Twitter: IntelTechniques Search Tool", "url": "https://inteltechniques.com/tools/Twitter.html" },
      { "title": "Twitter: Misc Tools", "url": "https://one-plus.github.io/Twitter" },
      { "title": "Twitter: Advanced Search", "url": "https://twitter.com/search-advanced" },
      { "title": "Twitter: Socialbearing", "url": "https://socialbearing.com/" },
      { "title": "Twitter: Twitonomy", "url": "https://www.twitonomy.com/" },
      { "title": "Twitter: Spoonbill", "url": "http://spoonbill.io/" },
      { "title": "Twitter: tinfoleak", "url": "https://tinfoleak.com/" },
      { "title": "Twitter: Analytics by Foller.me", "url": "https://foller.me/" },
      { "title": "Twitter: Analyze Followers", "url": "https://followerwonk.com/analyze" },
      { "title": "Instagram: IntelTechniques Search Tool", "url": "https://inteltechniques.com/tools/Instagram.html" },
      { "title": "Instagram: User ID", "url": "https://codeofaninja.com/tools/find-instagram-user-id/" },
      { "title": "Instagram: Picnob", "url": "https://www.picnob.com/profile/elonrmuskk/" },
      { "title": "Instagram: imginn", "url": "https://imginn.com/elonrmuskk/" },
      { "title": "Reddit: Search", "url": "https://camas.unddit.com/" },
      { "title": "Reddit: user-analyser", "url": "https://reddit-user-analyser.netlify.app/" },
      { "title": "Telegram: search", "url": "https://cse.google.com/cse?cx=006368593537057042503:efxu7xprihg#gsc.tab=0" },
      { "title": "Telegram: Tools collection", "url": "https://github.com/cqcore/Telegram-OSINT" },
      { "title": "Multi: Socialblade", "url": "https://socialblade.com/" },
      { "title": "Multi: Google Social Search", "url": "https://www.social-searcher.com/google-social-search/" },
      { "title": "Multi: Social Searcher", "url": "https://www.social-searcher.com/" },
      { "title": "Multi: Social-Media-OSINT-Tools-Collection", "url": "https://github.com/osintambition/Social-Media-OSINT-Tools-Collection" }
    ]
  },
  {
    "widgetTitle": "Domain OSINT",
    "bookmarks": [
      { "title": "Vortimo OSINT Tool", "url": "https://osint-tool.com/" },
      { "title": "intelx Domain", "url": "https://intelx.io/tools?tab=domain" },
      { "title": "Web Check", "url": "https://web-check.as93.net/" },
      { "title": "BuiltWith Technology Lookup", "url": "https://builtwith.com/" },
      { "title": "Free online network tools", "url": "https://centralops.net/co/" },
      { "title": "Reverse IP", "url": "https://dnslytics.com/reverse-ip" },
      { "title": "SpyOnWeb", "url": "https://spyonweb.com/" },
      { "title": "Visualping", "url": "https://visualping.io/" },
      { "title": "ViewDNS.info", "url": "https://viewdns.info/" },
      { "title": "Urldna.io", "url": "https://urldna.io/" },
      { "title": "Find Subdomains Online", "url": "https://pentest-tools.com/information-gathering/find-subdomains-of-domain" },
      { "title": "CRT Certificate Search", "url": "https://crt.sh/" },
      { "title": "Wayback Machine", "url": "https://web.archive.org/" },
      { "title": "VirusTotal", "url": "https://www.virustotal.com/gui/home/upload" },
      { "title": "Shodan", "url": "https://www.shodan.io/" },
      { "title": "MoonSearch Backlinks checker", "url": "http://moonsearch.com/" },
      { "title": "Criminal IP", "url": "https://www.criminalip.io/" },
      { "title": "Threat Crowd", "url": "https://threatcrowd.org/" },
      { "title": "LeakIX", "url": "https://leakix.net/" },
      { "title": "FullHunt", "url": "https://fullhunt.io/" },
      { "title": "www.cyber-xray.com", "url": "https://www.cyber-xray.com/#/search" },
      { "title": "Falcon Recon", "url": "https://falcon.crowdstrike.com/intelligence-v2/recon" },
      { "title": "Whois Lookup", "url": "https://whois.domaintools.com/" },
      { "title": "MXtoolbox", "url": "https://mxtoolbox.com/" },
      { "title": "Who.is", "url": "https://who.is/" },
      { "title": "DeHashed — #FreeThePassword", "url": "https://dehashed.com/" },
      { "title": "Netlas", "url": "https://app.netlas.io/host/" },
      { "title": "LeakCheck", "url": "https://leakcheck.io/" },
      { "title": "binaryedge.io", "url": "https://app.binaryedge.io/services/query" },
      { "title": "Pulsedive", "url": "https://pulsedive.com/" },
      { "title": "Censys", "url": "https://search.censys.io/" },
      { "title": "FOFA Search Engine", "url": "https://en.fofa.info/" },
      { "title": "dnsdumpster", "url": "https://dnsdumpster.com/" },
      { "title": "OSINT.SH", "url": "https://osint.sh/" }
    ]
  },
  {
    "widgetTitle": "Password/Leaks OSINT",
    "bookmarks": [
      { "title": "DeHashed", "url": "https://dehashed.com/" },
      { "title": "LeakCheck", "url": "https://leakcheck.io/" },
      { "title": "Snusbase Database Search Engine", "url": "https://snusbase.com/dashboard" },
      { "title": "Have I been pwned?", "url": "https://haveibeenpwned.com/" },
      { "title": "Leakpeek.com", "url": "https://leakpeek.com/" },
      { "title": "PSBDMP", "url": "https://psbdmp.ws/" },
      { "title": "Dark Web Exposure", "url": "https://www.immuniweb.com/darkweb/" },
      { "title": "Leak-lookup.com", "url": "https://leak-lookup.com/" }
    ]
  },
  {
    "widgetTitle": "Business OSINT",
    "bookmarks": [
      { "title": "The Company Database", "url": "https://www.aihitdata.com/" },
      { "title": "OpenCorporates", "url": "https://opencorporates.com/" }
    ]
  },
  {
    "widgetTitle": "Phone Number",
    "bookmarks": [
      { "title": "IntelTechniques Telephone Search Tool", "url": "https://inteltechniques.com/tools/Telephone.html" },
      { "title": "intelx.io Misc Telephone Tools", "url": "https://intelx.io/tools?tab=telephone" },
      { "title": "Truecaller.com", "url": "https://www.truecaller.com/" },
      { "title": "SYNC.me", "url": "https://sync.me/" },
      { "title": "How can I find a Google account with a phone number?", "url": "https://www.aware-online.com/en/how-can-i-find-a-google-account-by-phone-number/" },
      { "title": "Epieos", "url": "https://epieos.com/" },
      { "title": "NumLookup", "url": "https://www.numlookup.com/" },
      { "title": "Seon.io", "url": "https://seon.io/" },
      { "title": "Telegram Web", "url": "https://web.telegram.org/k/#@UniversalSearchRobot" },
      { "title": "osint.rocks", "url": "https://osint.rocks/" }
    ]
  },
  {
    "widgetTitle": "Faces",
    "bookmarks": [
      { "title": "Faceagle| Face search engine", "url": "https://faceagle.com/" }
    ]
  },
  {
    "widgetTitle": "Geolocation",
    "bookmarks": [
      { "title": "Agent.earthkit.app", "url": "https://agent.earthkit.app/" },
      { "title": "GeoSpy AI", "url": "https://geospy.ai/" },
      { "title": "Login - UserSearch.ai", "url": "https://usersearch.ai/" },
      { "title": "Find Photo Location Using AI", "url": "https://picarta.ai/" },
      { "title": "Geolocation Estimation", "url": "https://labs.tib.eu/geoestimation/" }
    ]
  },
  { "widgetTitle": "Email Osint Workflow", "bookmarks": [] },
  { "widgetTitle": "Name OSINT Workflow", "bookmarks": [] },
  { "widgetTitle": "Username OSINT Flowchart", "bookmarks": [] },
  { "widgetTitle": "Domain OSINT Flowchart", "bookmarks": [] },
  { "widgetTitle": "Phone OSINT Workflow", "bookmarks": [] },
  { "widgetTitle": "Location Osint Workfllow", "bookmarks": [] },
  { "widgetTitle": "Search Engines", "bookmarks": [] }
]

TARGET_DIR = r"c:/Users/yaniv/10Root Dropbox/Yaniv Radunsky/Documents/50-59 Projects/58 Gemini/58.01_OSINT-Searcher"

def sanitize_filename(title):
    # Keep only alphanumeric and spaces, replace spaces with underscores
    clean = re.sub(r'[^a-zA-Z0-9 ]', '', title)
    return clean.replace(' ', '_').strip() + '.html'

def generate_tool_card(title, url, index):
    # Unique ID for the script function
    func_name = f"doStartMeSearch{index}"
    
    html = f"""
            <div class="tool-card">
                <script type="text/javascript">
                    function {func_name}() {{ window.open('{url}', '_blank'); }}
                </script>
                <form class="tool-form" onsubmit="{func_name}(); return false;">
                    <input type="submit" value="{title}" style="width: 100%; white-space: normal;" />
                </form>
            </div>"""
    return html

def create_html_file(filename, title, bookmarks):
    file_path = os.path.join(TARGET_DIR, filename)
    
    tools_html = '        <div class="tools-grid">\n'
    if not bookmarks:
        tools_html += '            <p style="text-align:center; width:100%;">No tools found in this category.</p>\n'
    else:
        for idx, bm in enumerate(bookmarks):
            tools_html += generate_tool_card(bm['title'], bm['url'], idx)
    tools_html += '        </div>\n'
    
    # We use a placeholder for the sidebar which will be filled by restyle_app.py
    # But we need basic HTML structure so restyle_app.py recognizes it.
    
    # Actually, restyle_app.py expects:
    # <nav class="sidebar">...</nav>
    # <main class="main-content"> ... <div class="tools-grid">...
    
    # We can just generate a barebones structure and let restyle_app fill the sidebar
    
    content = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link rel="stylesheet" href="Files/style.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap" rel="stylesheet">
</head>
<body>

<div class="app-container">
    <!-- Sidebar -->
    <nav class="sidebar">
        <!-- Sidebar placeholder -->
    </nav>

    <!-- Main Content -->
    <main class="main-content">
        <div class="main-header">
            <h1>{title}</h1>
        </div>
{tools_html}
    </main>
</div>

</body>
</html>"""
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)
    print(f"Created {filename}")

def update_restyle_app(new_items):
    restyle_path = os.path.join(TARGET_DIR, "restyle_app.py")
    with open(restyle_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find SIDEBAR_ITEMS list
    # look for SIDEBAR_ITEMS = [ ... ]
    match = re.search(r'SIDEBAR_ITEMS = \[\s*([\s\S]*?)\]', content)
    if not match:
        print("Could not find SIDEBAR_ITEMS in restyle_app.py")
        return
        
    current_items_str = match.group(1)
    
    # Construct new items string
    new_items_str = ""
    for href, text in new_items:
        # Check if already exists to avoid duplicates in the code
        if f'("{href}", "{text}")' not in current_items_str and f"('{href}', '{text}')" not in current_items_str:
            new_items_str += f'    ("{href}", "{text}"),\n'
    
    if not new_items_str:
        print("No new items to add to sidebar.")
        return

    # Insert before the closing bracket of the list
    # We replace the whole list block to be safe, appending new items
    
    # Actually, simpler: just replace the last element's comma (if any) and append new items
    # But regex replacement of the whole block is safer/cleaner
    
    full_new_list_content = current_items_str.rstrip() + "\n" + new_items_str
    
    new_content = content.replace(current_items_str, full_new_list_content)
    
    with open(restyle_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print("Updated restyle_app.py with new sidebar items.")

def main():
    new_sidebar_items = []
    
    for widget in WIDGETS_DATA:
        title = widget['widgetTitle']
        bookmarks = widget['bookmarks']
        
        # Determine filename
        filename = sanitize_filename(title)
        
        # Create the page
        create_html_file(filename, title, bookmarks)
        
        # Add to list
        new_sidebar_items.append((filename, title))
        
    # Update restyle script
    update_restyle_app(new_sidebar_items)

if __name__ == "__main__":
    main()
