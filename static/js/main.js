const menuToggle = document.getElementById("menuToggle");
const sidebar = document.querySelector(".sidebar");
const sidebarOverlay = document.getElementById("sidebarOverlay");

if (menuToggle && sidebar && sidebarOverlay) {

    menuToggle.addEventListener("click", function () {
        sidebar.classList.toggle("show");
        sidebarOverlay.classList.toggle("show");
    });

    sidebarOverlay.addEventListener("click", function () {
        sidebar.classList.remove("show");
        sidebarOverlay.classList.remove("show");
    });

}

document.querySelectorAll(".sidebar-nav .nav-link").forEach(link => {
    link.addEventListener("click", function () {
        sidebar.classList.remove("show");
        sidebarOverlay.classList.remove("show");
    });
});