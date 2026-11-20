const dialog = document.getElementById("lightbox");
const dialogImg = document.getElementById("lightbox-img");
const dialogCaption = document.getElementById("lightbox-caption");

for (const trigger of document.querySelectorAll(".chart-trigger")) {
  trigger.addEventListener("click", () => {
    const innerImg = trigger.querySelector("img");
    dialogImg.src = trigger.dataset.fullSrc || innerImg.src;
    dialogImg.alt = innerImg.alt;
    dialogCaption.textContent = trigger.dataset.caption || innerImg.alt;
    dialog.showModal();
  });
}

dialog.addEventListener("close", () => {
  dialogImg.removeAttribute("src");
  dialogImg.alt = "";
});

if (!("closedBy" in HTMLDialogElement.prototype)) {
  dialog.addEventListener("click", (event) => {
    if (event.target !== dialog) return;
    const rect = dialog.getBoundingClientRect();
    const isDialogContent =
      rect.top <= event.clientY &&
      event.clientY <= rect.top + rect.height &&
      rect.left <= event.clientX &&
      event.clientX <= rect.left + rect.width;
    if (isDialogContent) return;
    dialog.close();
  });
}

/* Preserve active #section anchor when toggling EN <-> TR */
for (const langLink of document.querySelectorAll('.lang-switch a:not([aria-current="page"])')) {
  langLink.addEventListener("click", (event) => {
    if (!window.location.hash) return;
    event.preventDefault();
    window.location.href = langLink.href.split("#")[0] + window.location.hash;
  });
}
