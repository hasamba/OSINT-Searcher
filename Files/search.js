document.addEventListener('DOMContentLoaded', function () {
    const searchInput = document.getElementById('global-search');
    const resultsContainer = document.getElementById('search-results');

    // Ensure SITE_TOOLS is available
    if (typeof SITE_TOOLS === 'undefined') {
        console.error('SITE_TOOLS index not found.');
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
                item.href = tool.url;
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
