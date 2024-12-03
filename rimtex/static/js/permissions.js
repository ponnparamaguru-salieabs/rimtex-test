// static/js/permissions.js

function handleAjaxError(response) {
    if (response.status === 403) {
        response.json().then(data => {
            Swal.fire({
                title: 'Access Denied',
                text: data.error,
                icon: 'error',
                confirmButtonText: 'OK'
            });
        });
    }
}

$(document).ready(function() {
    $.ajax({
        url: '/your-url/',  // Change this to your URL
        type: 'GET',         // Change this to the method you are using
        success: function(data) {
            // Handle successful response
        },
        error: function(response) {
            handleAjaxError(response);
        }
    });
});
