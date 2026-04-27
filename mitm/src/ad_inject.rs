use html5ever::tendril::TendrilSink;
use html5ever::tree_builder::TreeBuilderOpts;
use markup5ever::rcdom::{RcDom, Handle, NodeData};
use std::default::Default;
use std::rc::Rc;

/// Injects a JavaScript snippet into the HTML head to remove ad elements.
pub fn inject_ad_blocker(html_bytes: &[u8]) -> Vec<u8> {
    let html_str = String::from_utf8_lossy(html_bytes);
    let script = r#"<script>
(function() {
    // Common ad selectors
    const selectors = [
        '.ad', '.ads', '.advertisement', '[class*="ad-"]', '[id*="ad-"]',
        'iframe[src*="doubleclick"]', 'div[data-ad]', '.banner-ad',
        '.sponsored', '.promoted'
    ];
    selectors.forEach(sel => {
        document.querySelectorAll(sel).forEach(el => el.remove());
    });
})();
</script>"#;

    // Simple injection: insert before </head> if found, else before </body>
    if let Some(head_pos) = html_str.to_lowercase().find("</head>") {
        let mut result = html_str[..head_pos].to_string();
        result.push_str(script);
        result.push_str(&html_str[head_pos..]);
        result.into_bytes()
    } else if let Some(body_pos) = html_str.to_lowercase().find("</body>") {
        let mut result = html_str[..body_pos].to_string();
        result.push_str(script);
        result.push_str(&html_str[body_pos..]);
        result.into_bytes()
    } else {
        html_bytes.to_vec()
    }
}