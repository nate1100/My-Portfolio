<script src="sweetalert.min.js"></script>
<form method="POST" action="do-something.php" onsubmit="return submitForm(this);">
    <input type="submit" />
</form>

<script>
    function submitForm(form) {
        Swal.fire({
            icon: 'error',
            title: 'Oops...',
            text: 'Something went wrong!',
            });
        return false;
        }
</script>