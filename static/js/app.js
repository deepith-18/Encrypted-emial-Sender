// static/js/app.js

$(document).ready(function() {
    // Intercept the compose form submission
    $('#compose-form').on('submit', function(e) {
        // Prevent the default browser page reload
        e.preventDefault();

        // Show a loading pop-up
        Swal.fire({
            title: 'Encrypting & Sending...',
            text: 'Please wait while we secure your message.',
            allowOutsideClick: false,
            didOpen: () => {
                Swal.showLoading();
            }
        });

        // Send the form data in the background
        $.ajax({
            url: '/compose_ajax', // The special route we created in Flask
            type: 'POST',
            data: $(this).serialize(),
            success: function(response) {
                if (response.success) {
                    Swal.fire({
                        icon: 'success',
                        title: 'Sent!',
                        text: response.message,
                    });
                    $('#compose-form')[0].reset(); // Clear the form after success
                } else {
                    Swal.fire({
                        icon: 'error',
                        title: 'Oops...',
                        text: response.message,
                    });
                }
            },
            error: function() {
                Swal.fire({
                    icon: 'error',
                    title: 'Network Error',
                    text: 'Could not send the email. Please try again later.',
                });
            }
        });
    });
});