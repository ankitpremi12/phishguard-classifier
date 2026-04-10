const DOMAIN_RE = /(?:https?:\/\/|ftp:\/\/)?(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?=[\s,;|"'\]>)<\n\r]|$)/gm;
function test(rawText) {
  const text = rawText.replace(/[\u200B-\u200D\uFEFF]/g, '');
  const matches = text.match(DOMAIN_RE) || [];
  console.log('Matches:', matches);
}
test("Domain axisbank.com bandhanbank.com cityunionbank.com");
test("google.com, amazon.com");
test("https://www.google.com/");
test("axisbank.com\nbandhanbank.com");
