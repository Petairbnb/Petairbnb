// PetAirbnb (PAWAirbnb) website functionality
(function() {
    'use strict';

    // Debounce function for search
    function debounce(func, delay) {
        let debounceTimer;
        return function() {
            const context = this;
            const args = arguments;
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => func.apply(context, args), delay);
        }
    }

    // Search for Hosts
    const searchHosts = debounce(async function() {
        const location = document.getElementById('location-search').value.trim();
        const resultsContainer = document.getElementById('search-results-container');

        if (!location) {
            displayErrorMessage('Please enter a location.');
            return;
        }

        showLoadingSpinner(resultsContainer);

        try {
            const response = await fetch(`/hosts?location=${encodeURIComponent(location)}`, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const data = await response.json();
            displayHostResults(data);
            scrollToResults();
        } catch (error) {
            console.error('Error fetching hosts:', error);
            displayErrorMessage('An error occurred while searching for hosts. Please try again later.');
        }
    }, 300);

    // Display host results
    function displayHostResults(hosts) {
        const resultsContainer = document.getElementById('search-results-container');
        resultsContainer.innerHTML = '';

        if (hosts.length === 0) {
            displayErrorMessage('No hosts found for this location.');
            return;
        }

        const resultsList = document.createElement('ul');
        resultsList.className = 'host-results';
        resultsList.setAttribute('aria-label', 'Host search results');

        hosts.forEach(host => {
            const hostItem = document.createElement('li');
            hostItem.className = 'host-card';
            hostItem.innerHTML = `
                <img src="${host.image}" alt="${host.name}'s profile picture">
                <h3>${host.name}</h3>
                <p>Location: ${host.location}</p>
                <div class="rating" aria-label="Rating: ${host.rating} out of 5 stars">
                  ${generateStarRating(host.rating)} 
                </div>
                <p>Rate: £${host.rate}/night</p>
                <button class="btn" onclick="viewHostProfile(${host.id})">View Profile</button>
            `;
            resultsList.appendChild(hostItem);
        });

        resultsContainer.appendChild(resultsList);
    }

    // Utility functions
    function showLoadingSpinner(container) {
        container.innerHTML = '<div class="loading-spinner" aria-label="Loading..."></div>';
    }

    function generateStarRating(rating) {
        return Array(5).fill().map((_, index) => 
            `<i class="${index < rating ? 'fas' : 'far'} fa-star" aria-hidden="true"></i>`
        ).join('');
    }

    function displayErrorMessage(message) {
        const resultsContainer = document.getElementById('search-results-container');
        resultsContainer.innerHTML = `<p class="error-message" role="alert">${message}</p>`;
    }

    function scrollToResults() {
        document.getElementById('search-results').scrollIntoView({ behavior: 'smooth' });
    }

    // View Host Profile
    async function viewHostProfile(hostId) {
        try {
            const response = await fetch(`/host/${hostId}`, {
                headers: { 'X-Requested-With': 'XMLHttpRequest' }
            });
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            const hostData = await response.json();
            displayHostProfile(hostData);
        } catch (error) {
            console.error('Error fetching host profile:', error);
            alert('Failed to load host profile. Please try again later.');
        }
    }

    function displayHostProfile(hostData) {
        // Implement based on your UI design
        console.log('Host profile data:', hostData);
    }

    // PAWVET Chat
    function startPAWVETChat() {
        const chatWindow = window.open('https://chat.petairbnb.co.uk', 'PAWVET Chat', 'width=400,height=600');
        if (!chatWindow) {
            alert('Failed to open PAWVET chat window. Please allow pop-ups and try again.');
        }
    }

    // Form visibility toggling
    function toggleFormVisibility(showId, hideId) {
        const showForm = document.getElementById(showId);
        const hideForm = document.getElementById(hideId);
        if (showForm && hideForm) {
            showForm.style.display = 'block';
            hideForm.style.display = 'none';
            showForm.querySelector('input').focus();
        }
    }

    // Form handling
    function handleFormSubmit(event) {
        event.preventDefault();
        if (!validateForm(event.target)) return;

        const formData = new FormData(event.target);
        fetch(event.target.action, {
            method: event.target.method,
            body: formData,
            headers: { 
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': getCsrfToken()
            }
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return response.json();
        })
        .then(result => {
            console.log('Form submission successful:', result);
            alert('Form submitted successfully!');
            event.target.reset();
        })
        .catch(error => {
            console.error('Error submitting form:', error);
            alert('An error occurred while submitting the form. Please try again later.');
        });
    }

    function validateForm(form) {
        let isValid = true;
        form.querySelectorAll('input, select, textarea').forEach(element => {
            if (element.hasAttribute('required') && !element.value.trim()) {
                isValid = false;
                element.classList.add('error');
                const errorMessage = document.createElement('span');
                errorMessage.className = 'error-message';
                errorMessage.textContent = 'This field is required';
                element.parentNode.appendChild(errorMessage);
            }
        });
        return isValid;
    }

    function getCsrfToken() {
        return document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    }

    // Event Listeners
    document.addEventListener('DOMContentLoaded', () => {
        const searchInput = document.getElementById('location-search');
        if (searchInput) {
            searchInput.addEventListener('input', searchHosts);
        }

        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', handleFormSubmit);
        });

        // Expose global functions
        window.viewHostProfile = viewHostProfile;
        window.startPAWVETChat = startPAWVETChat;
        window.showPetOwnerForm = () => toggleFormVisibility('pet-owner-form', 'host-form');
        window.showHostForm = () => toggleFormVisibility('host-form', 'pet-owner-form');
    });
})();
