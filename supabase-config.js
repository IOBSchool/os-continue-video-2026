// ============================================================
// ★ ここだけ書き換えればOKです（Supabaseの設定）
// Daily Letters（OS継続コース）アウトプットページ用
// ============================================================

const SUPABASE_URL  = 'https://kctwhkxnvfidsnqaoefh.supabase.co';
const SUPABASE_KEY  = 'sb_publishable_6vtlwnwq3Mi0t6XdGxQN7g_0VFm5PTU';

// 管理画面のパスワードはここには置かない（公開ページから誰でも読めてしまうため）。
// Supabase 側でハッシュ照合している。変更手順は supabase/README.md を参照。
//
// このページは B社（employee-training）のアウトプット月間ページと同じ Supabase を
// 共有しているが、テーブルは dl_output_questions / dl_output_responses に完全分離。
// B社のデータ（output_questions / output_responses）とは混ざらない。
