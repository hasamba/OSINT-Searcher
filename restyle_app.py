
import os
import re

TARGET_DIR = r"c:/Users/yaniv/10Root Dropbox/Yaniv Radunsky/Documents/50-59 Projects/58 Gemini/58.01_OSINT-Searcher"

SIDEBAR_ITEMS = [
    ("Search.html", "Search Engines"),
    ("Facebook.html", "Facebook"),
    ("Twitter.html", "X (Twitter)"),
    ("Instagram.html", "Instagram"),
    ("LinkedIn.html", "LinkedIn"),
    ("Communities.html", "Communities"),
    ("Email.html", "Email Addresses"),
    ("Username.html", "Usernames"),
    ("Name.html", "Names"),
    ("Address.html", "Addresses"),
    ("Telephone.html", "Telephone Numbers"),
    ("Location.html", "Maps"),
    ("Documents.html", "Documents"),
    ("Images.html", "Images"),
    ("Videos.html", "Videos"),
    ("Domain.html", "Domains"),
    ("IP.html", "IP Addresses"),
    ("Business.html", "Business & Gov"),
    ("Vehicle.html", "Vehicles"),
    ("Currencies.html", "Virtual Currencies"),
    ("Breaches.html", "Data Breaches"),
    ("Radio.html", "Live Audio"),
    ("Video.html", "Live Video"),
    ("API.html", "APIs"),
    ("Phishing_EmailSuspicious_URL.html", "Phishing Email/Suspicious URL"),
    ("PhisingMalware_Analysis.html", "Phising/Malware Analysis"),
    ("Threat_Hunting.html", "Threat Hunting"),
    ("Hashes_to_Hashes.html", "Hashes to Hashes"),
    ("Malware_Related.html", "Malware Related"),
    ("Sandbox.html", "Sandbox"),
    ("GoogleShodan_Dorks.html", "Google/Shodan Dorks"),
    ("URLIP_Scan.html", "URL/IP Scan"),
    ("Social_Serch.html", "Social Serch"),
    ("Courses.html", "Courses"),
    ("OSINT_Frameworks.html", "OSINT Frameworks"),
    ("Username_OSINT.html", "Username OSINT"),
    ("Full_Name_OSINT.html", "Full Name OSINT"),
    ("Emails_OSINT.html", "Emails OSINT"),
    ("Photos_OSINT.html", "Photos OSINT"),
    ("Social_Media_OSINT.html", "Social Media OSINT"),
    ("Domain_OSINT.html", "Domain OSINT"),
    ("PasswordLeaks_OSINT.html", "Password/Leaks OSINT"),
    ("Business_OSINT.html", "Business OSINT"),
    ("Phone_Number.html", "Phone Number"),
    ("Faces.html", "Faces"),
    ("Geolocation.html", "Geolocation"),
    ("Search_Engines.html", "Search Engines"),
]

def generate_sidebar(active_file):
    html = '    <nav class="sidebar">\n'
    html += '        <div class="sidebar-header">\n'
    html += '            <h2>OSINT Searcher</h2>\n'
    html += '        </div>\n'
    html += '        <ul class="nav-links">\n'
    
    for href, text in SIDEBAR_ITEMS:
        # Determine active
        is_active = (href == active_file)
        cls = ' class="active"' if is_active else ''
        html += f'            <li><a href="{href}"{cls}>{text}</a></li>\n'
        
    html += '        </ul>\n'
    html += '    </nav>\n'
    return html

def process_file(filename):
    file_path = os.path.join(TARGET_DIR, filename)
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Skip if already modernized (check for tools-grid class)
    # if 'class="tools-grid"' in content:
    #    print(f"Skipping body rewrite for {filename} (already modernized)")
    #    return

    # Extract Title
    title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
    title = title_match.group(1) if title_match else "OSINT Searcher"
    
    # Clean Title for Sidebar/Meta
    title = title.replace('IntelTechniques ', '')

    # Extract Main Content
    # Pattern looks for the Sidebar TD then the Content TD
    # Matches <td width="..."> [sidebar] </td> <td width="..."> [CONTENT] </td>
    
    # Updated regex to handle the new modernized layout if we are re-processing
    # If the file is already modernized, we need to extract from the <main> block
    
    if 'class="tools-grid"' in content:
        # It's already modernized, let's just update the sidebar and title
        print(f"Updating modernized file: {filename}")
        
        # Update Title
        new_content = re.sub(r'<title>.*?</title>', f'<title>{title}</title>', content)
        
        # Update H1
        clean_title_h1 = title.replace(' Tool', '')
        new_content = re.sub(r'<h1>.*?</h1>', f'<h1>{clean_title_h1}</h1>', new_content)
        
        # Update Sidebar
        sidebar_content = generate_sidebar(filename)
        new_content = re.sub(r'<nav class="sidebar">[\s\S]*?</nav>', sidebar_content.strip(), new_content)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        return

    match = re.search(r'<td\s+width="[0-9]+">\s*<ul>[\s\S]*?</ul>\s*</td>\s*<td\s+width="[0-9]+">([\s\S]*?)</td>\s*</tr>', content, re.IGNORECASE)
    
    if not match:
        print(f"Warning: Could not parse content table in {filename}")
        return

    raw_content = match.group(1)
    
     # Identify tools: Script + Form pairs
    # We split by regex to preserve order of text vs tools
    
    tool_pattern = re.compile(r'(<script[\s\S]*?</script>)\s*(?:<br>\s*)*\s*(<form[\s\S]*?</form>)', re.IGNORECASE)
    
    parts = tool_pattern.split(raw_content)
    
    new_body_content = ""
    current_grid_items = []
    
    def flush_grid():
        nonlocal new_body_content, current_grid_items
        if current_grid_items:
            new_body_content += '        <div class="tools-grid">\n'
            for item in current_grid_items:
                new_body_content += item
            new_body_content += '        </div>\n'
            current_grid_items = []

    # Iterate parts
    i = 0
    while i < len(parts):
        text_segment = parts[i]
        
        # Clean text
        clean_text = text_segment.strip()
        # Remove leading/trailing <br>s
        clean_text = re.sub(r'^(<br\s*/?>\s*)+', '', clean_text, flags=re.IGNORECASE)
        clean_text = re.sub(r'(<br\s*/?>\s*)+$', '', clean_text, flags=re.IGNORECASE)
        
        if clean_text:
            flush_grid()
            # Wrap headers/text 
            # If it looks like a header (short, bold?), keep it.
            # We'll just wrap in a generic container
            new_body_content += f'        <div class="mb-4 text-center">{clean_text}</div>\n'
        
        # Check if next parts are Script/Form (captured by split)
        if i + 1 < len(parts):
            script = parts[i+1]
            form = parts[i+2]
            
            # Clean Form
            form = re.sub(r'style="width:140px"', '', form)
            form = re.sub(r'size="30"', '', form)
            form = form.replace('<br></form>', '</form>')
            form = re.sub(r'<form', '<form class="tool-form"', form)

            card_html = f'            <div class="tool-card">\n{script}\n{form}\n            </div>\n'
            current_grid_items.append(card_html)
            
            i += 3
        else:
            i += 1
            
    flush_grid()
    
    # Headers
    clean_title = title.replace(' Tool', '')
    
    full_html = f"""<!doctype html>
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
{generate_sidebar(filename)}
    <!-- Main Content -->
    <main class="main-content">
        <div class="main-header">
            <h1>{clean_title}</h1>
        </div>
{new_body_content}
    </main>
</div>

</body>
</html>"""

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(full_html)
    print(f"Processed {filename}")

def update_sidebar_only(filename):
    file_path = os.path.join(TARGET_DIR, filename)
    with open(file_path, 'r', encoding='utf-8') as f:
         content = f.read()
    
    sidebar_content = generate_sidebar(filename)
    # Regex to find existing sidebar
    # Pattern: <nav class="sidebar"> ... </nav>
    # Be careful with greedy matching if parsing is hard.
    # Assuming <nav class="sidebar"> is unique.
    
    new_content = re.sub(r'<nav class="sidebar">[\s\S]*?</nav>', sidebar_content.strip(), content)
    
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(new_content)
    print(f"Updated sidebar for {filename}")

def main():
    files = os.listdir(TARGET_DIR)
    for f in files:
        if f.endswith(".html"):
             if f == "index.html":
                 continue # Handle index separately
             
             if f == "Username.html":
                 update_sidebar_only(f)
             else:
                 process_file(f)

    # Handle index.html - Redirect to Search.html
    index_path = os.path.join(TARGET_DIR, "index.html")
    index_content = """<!doctype html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="0; url=Search.html" />
    <title>Redirecting...</title>
</head>
<body>
    <p>Redirecting to <a href="Search.html">Search Tools</a>...</p>
</body>
</html>
"""

    with open(index_path, 'w', encoding='utf-8') as f:
        f.write(index_content)
    print("Updated index.html to redirect")

if __name__ == "__main__":
    main()
