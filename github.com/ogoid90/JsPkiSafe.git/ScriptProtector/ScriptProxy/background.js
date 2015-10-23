// alternative to DOMContentLoaded
document.onreadystatechange = function () {
  if (document.readyState == "interactive") {
    alert(1);
  }
}
// alternative to load event
document.onreadystatechange = function () {
  if (document.readyState == "complete") {
    alert(2);
  }
}