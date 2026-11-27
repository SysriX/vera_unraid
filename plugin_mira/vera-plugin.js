/* VERA plugin for MIRA – uses the same views as VERA itself (vera-views.js + wireguard.js). */
"use strict";

miraPlugin("vera", ctx => veraViews({
  api: ctx.api,
  link: ctx.link,
  can: ctx.can,
  rerender: ctx.rerender,
  meId: null,
  shareUrl: t => `${ctx.conn.base_url}/wg-share/${t}`,   // share links are served by VERA itself
}));
