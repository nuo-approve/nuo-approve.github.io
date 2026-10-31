// The sites whose staging editor may ask this page for an approval or a passkey: each one's staging origin, exactly.
// A request from anywhere else is ignored, so a look-alike page can't use this one. A new site goes in here, then a
// release, then nuo_sync.py --approve.
export const SITES = ['https://staging.nuordinary.com'];
