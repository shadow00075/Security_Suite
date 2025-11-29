/**
 * Main JavaScript for Capstone Security Suite
 * Provides common functionality across all pages
 */

$(document).ready(function() {
    // Initialize application
    initializeApp();
    
    // Set up global event handlers
    setupGlobalHandlers();
    
    // Clock functionality removed for cleaner interface
});

/**
 * Initialize application
 */
function initializeApp() {
    // Load the user preferences
    loadUserPreferences();
    
    // Init tooltips
    initializeTooltips();
    
    // Set up CSRF token for AJAX requests
    setupCSRFToken();
    
    // Initialize notifications
    initializeNotifications();
    
    console.log('Capstone Security Suite initialized');
}

/**
 * Set up event handlers globally
 */
function setupGlobalHandlers() {
    // Handle AJAX errors globally
    $(document).ajaxError(function(event, xhr, settings, thrownError) {
        if (xhr.status === 0) {
            showNotification('Network connection lost. Please check your connection.', 'error');
        } else if (xhr.status >= 500) {
            showNotification('Server error occurred. Please try again later.', 'error');
        } else if (xhr.status === 404) {
            showNotification('Requested resource not found.', 'warning');
        }
    });
    
    // Handle form submissions with loading states
    $('form').on('submit', function() {
        const submitBtn = $(this).find('button[type="submit"]');
        if (submitBtn.length) {
            const originalText = submitBtn.html();
            submitBtn.html('<i class="fas fa-spinner fa-spin"></i> Processing...');
            submitBtn.prop('disabled', true);
            
            // Re-enable after 30 seconds as failsafe
            setTimeout(function() {
                submitBtn.html(originalText);
                submitBtn.prop('disabled', false);
            }, 30000);
        }
    });
    
    // Handle copy-to-clipboard functionality
    $('.copy-button').on('click', function() {
        const target = $(this).data('copy-target');
        const text = $(target).val() || $(target).text();
        
        copyToClipboard(text);
        showNotification('Copied to clipboard!', 'success');
    });
    
    // Handle keyboard shortcuts
    $(document).on('keydown', function(e) {
        // Ctrl+/ or Cmd+/ for help
        if ((e.ctrlKey || e.metaKey) && e.key === '/') {
            e.preventDefault();
            showHelpModal();
        }
        
        // Escape key to close modals
        if (e.key === 'Escape') {
            $('.modal.show').modal('hide');
        }
    });
}

/**
 * Clock functionality removed for cleaner interface
 */

/**
 * Load user preferences from localStorage
 */
function loadUserPreferences() {
    try {
        const theme = localStorage.getItem('theme') || 'light';
        const notifications = localStorage.getItem('notifications') !== 'false';
        
        applyTheme(theme);
        setNotificationsEnabled(notifications);
        
    } catch (error) {
        console.warn('Could not load user preferences:', error);
    }
}

/**
 * Apply theme to the application
 */
function applyTheme(theme) {
    document.body.className = document.body.className.replace(/theme-\w+/g, '');
    
    if (theme === 'dark') {
        document.body.classList.add('dark-mode');
    } else if (theme === 'auto') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        if (prefersDark) {
            document.body.classList.add('dark-mode');
        }
    }
}

/**
 * Initialize tooltips
 */
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

/**
 * Setup CSRF token for AJAX requests
 */
function setupCSRFToken() {
    const token = $('meta[name=csrf-token]').attr('content');
    if (token) {
        $.ajaxSetup({
            beforeSend: function(xhr, settings) {
                if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
                    xhr.setRequestHeader("X-CSRFToken", token);
                }
            }
        });
    }
}

/**
 * Initialize notification system
 */
function initializeNotifications() {
    // Check if notifications are supported
    if ('Notification' in window) {
        // Request permission if not already granted
        if (Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }
}

/**
 * Set notifications enabled state
 */
function setNotificationsEnabled(enabled) {
    localStorage.setItem('notifications', enabled.toString());
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info', duration = 5000) {
    const alertClass = getAlertClass(type);
    const iconClass = getIconClass(type);
    
    const notification = $(`
        <div class="alert ${alertClass} alert-dismissible fade show position-fixed notification" 
             style="top: 80px; right: 20px; z-index: 1055; max-width: 400px;" role="alert">
            <i class="${iconClass} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    `);
    
    $('body').append(notification);
    
    // Auto-dismiss after duration
    if (duration > 0) {
        setTimeout(function() {
            notification.fadeOut(300, function() {
                $(this).remove();
            });
        }, duration);
    }
    
    // Show browser notification if enabled and permission granted
    if (localStorage.getItem('notifications') !== 'false' && 
        'Notification' in window && 
        Notification.permission === 'granted') {
        
        new Notification('Security Suite', {
            body: message,
            icon: '/static/favicon.ico'
        });
    }
}

/**
 * Get Bootstrap alert class for notification type
 */
function getAlertClass(type) {
    const classes = {
        'success': 'alert-success',
        'error': 'alert-danger',
        'warning': 'alert-warning',
        'info': 'alert-info'
    };
    return classes[type] || 'alert-info';
}

/**
 * Get Font Awesome icon class for notification type
 */
function getIconClass(type) {
    const icons = {
        'success': 'fas fa-check-circle',
        'error': 'fas fa-exclamation-triangle',
        'warning': 'fas fa-exclamation-circle',
        'info': 'fas fa-info-circle'
    };
    return icons[type] || 'fas fa-info-circle';
}

/**
 * Copy text to clipboard
 */
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        return navigator.clipboard.writeText(text);
    } else {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            textArea.remove();
            return Promise.resolve();
        } catch (error) {
            textArea.remove();
            return Promise.reject(error);
        }
    }
}

/**
 * Format file size in human readable format
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format duration in human readable format
 */
function formatDuration(seconds) {
    const units = [
        { label: 'd', value: 86400 },
        { label: 'h', value: 3600 },
        { label: 'm', value: 60 },
        { label: 's', value: 1 }
    ];
    
    let result = '';
    let remaining = seconds;
    
    for (const unit of units) {
        const value = Math.floor(remaining / unit.value);
        if (value > 0) {
            result += `${value}${unit.label} `;
            remaining %= unit.value;
        }
    }
    
    return result.trim() || '0s';
}

/**
 * Validate IP address
 */
function isValidIP(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

/**
 * Validate domain name
 */
function isValidDomain(domain) {
    const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/;
    return domainRegex.test(domain);
}

/**
 * Validate URL
 */
function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

/**
 * Debounce function to limit API calls
 */
function debounce(func, delay) {
    let timeoutId;
    return function(...args) {
        clearTimeout(timeoutId);
        timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
}

/**
 * Throttle function to limit function execution
 */
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}

/**
 * Generate random ID
 */
function generateId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

/**
 * Load and display data in a table
 */
function loadDataTable(containerId, data, columns) {
    const container = $(`#${containerId}`);
    
    if (!data || data.length === 0) {
        container.html('<p class="text-muted text-center">No data available</p>');
        return;
    }
    
    let html = '<div class="table-responsive"><table class="table table-striped table-hover">';
    
    // Header
    html += '<thead><tr>';
    columns.forEach(col => {
        html += `<th>${col.title}</th>`;
    });
    html += '</tr></thead>';
    
    // Body
    html += '<tbody>';
    data.forEach(row => {
        html += '<tr>';
        columns.forEach(col => {
            let value = row[col.field] || '';
            if (col.formatter) {
                value = col.formatter(value, row);
            }
            html += `<td>${value}</td>`;
        });
        html += '</tr>';
    });
    html += '</tbody>';
    
    html += '</table></div>';
    container.html(html);
}

/**
 * Show loading spinner
 */
function showLoading(containerId) {
    $(`#${containerId}`).html(`
        <div class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mt-2 text-muted">Loading...</p>
        </div>
    `);
}

/**
 * Show error message
 */
function showError(containerId, message) {
    $(`#${containerId}`).html(`
        <div class="alert alert-danger" role="alert">
            <i class="fas fa-exclamation-triangle me-2"></i>
            ${message}
        </div>
    `);
}

/**
 * Show help modal
 */
function showHelpModal() {
    const helpModal = new bootstrap.Modal(document.getElementById('helpModal') || createHelpModal());
    helpModal.show();
}

/**
 * Create help modal if it doesn't exist
 */
function createHelpModal() {
    const modalHtml = `
        <div class="modal fade" id="helpModal" tabindex="-1" aria-labelledby="helpModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="helpModalLabel">
                            <i class="fas fa-question-circle me-2"></i>Help & Keyboard Shortcuts
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <h6>Keyboard Shortcuts</h6>
                        <ul>
                            <li><kbd>Ctrl</kbd> + <kbd>/</kbd> - Show this help dialog</li>
                            <li><kbd>Esc</kbd> - Close active modal</li>
                        </ul>
                        
                        <h6>Features</h6>
                        <ul>
                            <li><strong>Password Generator:</strong> Create secure passwords based on security questions</li>
                            <li><strong>Port Scanner:</strong> Scan network ports for security assessment</li>
                            <li><strong>Hash Generator:</strong> Generate and verify cryptographic hashes</li>
                            <li><strong>Network Analyzer:</strong> Analyze network interfaces and connections</li>
                            <li><strong>Vulnerability Scanner:</strong> Scan for common security vulnerabilities</li>
                            <li><strong>Intrusion Detection:</strong> Monitor network traffic for anomalies</li>
                        </ul>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    $('body').append(modalHtml);
    return document.getElementById('helpModal');
}

/**
 * Export functionality
 */
function exportData(data, filename, format = 'json') {
    let content, mimeType;
    
    if (format === 'json') {
        content = JSON.stringify(data, null, 2);
        mimeType = 'application/json';
    } else if (format === 'csv') {
        content = convertToCSV(data);
        mimeType = 'text/csv';
    } else {
        throw new Error('Unsupported export format');
    }
    
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    URL.revokeObjectURL(url);
}

/**
 * Convert data to CSV format
 */
function convertToCSV(data) {
    if (!data || data.length === 0) return '';
    
    const headers = Object.keys(data[0]);
    const csvContent = [
        headers.join(','),
        ...data.map(row => 
            headers.map(header => {
                const value = row[header] || '';
                return typeof value === 'string' && value.includes(',') 
                    ? `"${value}"` 
                    : value;
            }).join(',')
        )
    ].join('\n');
    
    return csvContent;
}

// Global error handler
window.onerror = function(message, source, lineno, colno, error) {
    console.error('Global error:', { message, source, lineno, colno, error });
    showNotification('An unexpected error occurred. Please refresh the page.', 'error');
    return false;
};

// Handle unhandled promise rejections
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
    showNotification('An error occurred. Please try again.', 'error');
});

// Export commonly used functions to global scope
window.SecuritySuite = {
    showNotification,
    copyToClipboard,
    formatFileSize,
    formatDuration,
    isValidIP,
    isValidDomain,
    isValidURL,
    debounce,
    throttle,
    generateId,
    loadDataTable,
    showLoading,
    showError,
    exportData
};