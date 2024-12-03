document.addEventListener("DOMContentLoaded", function() {
    const productTiles = document.querySelectorAll(".product-tile");

    productTiles.forEach(function(tile) {
        tile.addEventListener("click", function() {
            const productId = tile.getAttribute("data-product-id");
            window.location.href = `/adminproduct/edit/${productId}`;
        });
    });
});