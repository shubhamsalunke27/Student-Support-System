document.addEventListener('DOMContentLoaded', function() {
    // Socket.IO setup
    var socket = io();
    
    // Join complaint room if on complaint page
    if (document.querySelector('[data-complaint-id]')) {
        const complaintId = document.querySelector('[data-complaint-id]').dataset.complaintId;
        socket.emit('join', { room: `complaint_${complaintId}` });
    }
    
    // Handle real-time message updates
    socket.on('new_message', function(data) {
        const messagesContainer = document.querySelector('.messages-container');
        if (messagesContainer) {
            const messageHtml = `
                <div class="message ${data.sender_id === currentUserId ? 'sent' : 'received'}">
                    <div class="message-header">
                        <span class="sender">${data.sender_name}</span>
                        <span class="timestamp">${data.timestamp}</span>
                    </div>
                    <div class="message-content">${data.message}</div>
                </div>
            `;
            messagesContainer.insertAdjacentHTML('beforeend', messageHtml);
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    });
    
    // Handle flash messages
    const flashMessages = document.querySelector('.flash-messages');
    if (flashMessages) {
        setTimeout(() => {
            const alerts = flashMessages.querySelectorAll('.alert');
            alerts.forEach(alert => {
                alert.style.animation = 'slideOut 0.3s ease-in forwards';
                setTimeout(() => alert.remove(), 300);
            });
        }, 5000);
    }
    
    // Form validation
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;
            
            requiredFields.forEach(field => {
                if (!field.value.trim()) {
                    isValid = false;
                    field.classList.add('error');
                    
                    const errorMessage = document.createElement('div');
                    errorMessage.className = 'error-message';
                    errorMessage.textContent = `${field.getAttribute('name')} is required`;
                    
                    if (!field.nextElementSibling?.classList.contains('error-message')) {
                        field.parentNode.insertBefore(errorMessage, field.nextSibling);
                    }
                }
            });
            
            if (!isValid) {
                e.preventDefault();
            }
        });
        
        form.addEventListener('input', function(e) {
            if (e.target.classList.contains('error')) {
                e.target.classList.remove('error');
                const errorMessage = e.target.nextElementSibling;
                if (errorMessage?.classList.contains('error-message')) {
                    errorMessage.remove();
                }
            }
        });
    });
    
    // Dynamic form updates
    const adminLevelSelect = document.getElementById('admin_level');
    const adminPositionSelect = document.getElementById('admin_position');
    
    if (adminLevelSelect && adminPositionSelect) {
        adminLevelSelect.addEventListener('change', function() {
            const level = this.value;
            const positions = getPositionsForLevel(level);
            
            // Clear current options
            adminPositionSelect.innerHTML = '<option value="">Select Position</option>';
            
            // Add new options
            positions.forEach(position => {
                const option = document.createElement('option');
                option.value = position;
                option.textContent = position.replace('_', ' ').replace(/\w\S*/g, w => w.charAt(0).toUpperCase() + w.substr(1).toLowerCase());
                adminPositionSelect.appendChild(option);
            });
        });
    }
    
    // Upvote functionality
    const upvoteButtons = document.querySelectorAll('.upvote-button');
    upvoteButtons.forEach(button => {
        button.addEventListener('click', async function() {
            const complaintId = this.dataset.complaintId;
            try {
                const response = await fetch(`/student/complaint/${complaintId}/upvote`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                
                const data = await response.json();
                if (data.success) {
                    const countElement = this.querySelector('.upvote-count');
                    countElement.textContent = data.upvotes;
                    
                    if (data.action === 'added') {
                        this.classList.add('upvoted');
                    } else {
                        this.classList.remove('upvoted');
                    }
                }
            } catch (error) {
                console.error('Error updating upvote:', error);
            }
        });
    });
});

// Helper function to get admin positions based on level
function getPositionsForLevel(level) {
    const positions = {
        'academic': ['GFM', 'DAC', 'HOD', 'Dean', 'Principal', 'Secretary'],
        'hostel': ['Rector', 'Principal', 'Secretary'],
        'facilities': ['Lab_In_Charge', 'Department_Admin', 'Facility_Manager', 'Principal', 'Secretary'],
        'administration': ['Department_Admin', 'Office_Admin', 'Principal', 'Secretary']
    };
    return positions[level] || [];
}