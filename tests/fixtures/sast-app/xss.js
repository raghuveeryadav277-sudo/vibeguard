// VULN: xss
// Fixture: Cross-Site Scripting via innerHTML and document.write

function renderComment(userInput) {
  const el = document.getElementById('comment');
  // Unsafe: user input assigned directly to innerHTML
  el.innerHTML = userInput;
}

function renderSearch(query) {
  // Unsafe: document.write with user input
  document.write('<p>Results for: ' + query + '</p>');
}

module.exports = { renderComment, renderSearch };
