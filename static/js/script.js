document.addEventListener("DOMContentLoaded", () => {

    const scene = document.getElementById("blockchainScene");

    if (!scene) return;

    const reduceMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)"
    ).matches;

    if (reduceMotion) return;

    document.addEventListener("mousemove", (event) => {

        const x = (event.clientX / window.innerWidth) - 0.5;
        const y = (event.clientY / window.innerHeight) - 0.5;

        const rotateY = x * 16;
        const rotateX = y * -16;

        scene.style.setProperty(
            "--mouse-x",
            `${rotateY}deg`
        );

        scene.style.setProperty(
            "--mouse-y",
            `${rotateX}deg`
        );
    });

    /* Reset perspective when mouse leaves */

    document.addEventListener("mouseleave", () => {

        scene.style.setProperty(
            "--mouse-x",
            "0deg"
        );

        scene.style.setProperty(
            "--mouse-y",
            "0deg"
        );
    });

});