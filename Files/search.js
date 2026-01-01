document.addEventListener('DOMContentLoaded', function () {
    // --- Sidebar Scroll Persistence ---
    const sidebar = document.querySelector('.sidebar');
    if (sidebar) {
        // Restore scroll position
        const savedScroll = sessionStorage.getItem('sidebarScroll');
        if (savedScroll) {
            sidebar.scrollTop = savedScroll;
        }

        // Save scroll position on scroll
        sidebar.addEventListener('scroll', function () {
            sessionStorage.setItem('sidebarScroll', sidebar.scrollTop);
        });
    }

    const searchInput = document.getElementById('global-search');
    const resultsContainer = document.getElementById('search-results');

    // ---------------------------------------------------------
    // 1. HIGHLIGHT LOGIC (Run on every page load)
    // ---------------------------------------------------------
    const urlParams = new URLSearchParams(window.location.search);
    const highlightTerm = urlParams.get('highlight');

    if (highlightTerm) {
        // Find the tool card corresponding to the term
        // We look for input[type="submit"] with value == highlightTerm
        const toolCards = document.querySelectorAll('.tool-card');
        for (const card of toolCards) {
            const submitBtn = card.querySelector('input[type="submit"]');

            // Loose matching: allows part of the name or exact match
            if (submitBtn && submitBtn.value.toLowerCase().includes(highlightTerm.toLowerCase())) {
                // Scroll into view
                card.scrollIntoView({ behavior: 'smooth', block: 'center' });

                // Add highlight class
                card.classList.add('highlight-tool');

                // Remove highlight after animation (3s)
                setTimeout(() => {
                    card.classList.remove('highlight-tool');
                }, 3000);

                // Stop after first match to avoid jumping around
                break;
            }
        }
    }

    // ---------------------------------------------------------
    // 2. SEARCH BAR LOGIC
    // ---------------------------------------------------------

    // If search input doesn't exist (some pages might not have sidebar?), skip
    if (!searchInput) return;

    // Ensure SITE_TOOLS is available
    if (typeof SITE_TOOLS === 'undefined') {
        return;
    }

    searchInput.addEventListener('input', function (e) {
        const query = e.target.value.toLowerCase().trim();

        if (query.length < 2) {
            resultsContainer.style.display = 'none';
            resultsContainer.innerHTML = '';
            return;
        }

        const matches = SITE_TOOLS.filter(tool => tool.name.toLowerCase().includes(query));

        if (matches.length > 0) {
            resultsContainer.innerHTML = '';
            matches.slice(0, 15).forEach(tool => {
                const item = document.createElement('a');
                // Append ?highlight=ToolName to the URL
                item.href = `${tool.url}?highlight=${encodeURIComponent(tool.name)}`;
                item.className = 'search-result-item';
                item.innerHTML = `<strong>${tool.name}</strong> <span>in ${tool.category}</span>`;
                resultsContainer.appendChild(item);
            });
            resultsContainer.style.display = 'block';
        } else {
            resultsContainer.style.display = 'none';
        }
    });

    // Close on click outside
    document.addEventListener('click', function (e) {
        if (!searchInput.contains(e.target) && !resultsContainer.contains(e.target)) {
            resultsContainer.style.display = 'none';
        }
    });
});
