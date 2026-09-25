-- Daily Letters アウトプットページ セキュリティ設計
-- STEP 2: RLS を有効化し、公開キー(anon)からの直接アクセスを最小限に絞る。
-- 新しいページ(RPC版)が本番に出てから実行すること。
-- B社の output_* テーブルには一切触れない（DL専用の dl_output_* だけ）。

alter table public.dl_output_questions enable row level security;
alter table public.dl_output_responses enable row level security;

-- テーブル権限をいったん全部外し、必要なものだけ戻す
revoke all on public.dl_output_questions, public.dl_output_responses from anon, authenticated;
grant select on public.dl_output_questions to anon, authenticated;   -- 今の問いの表示・keepalive
grant insert on public.dl_output_responses to anon, authenticated;   -- 回答の送信のみ（読み・更新・削除は不可）

drop policy if exists dl_output_questions_public_read on public.dl_output_questions;
create policy dl_output_questions_public_read on public.dl_output_questions
  for select to anon, authenticated using (true);

drop policy if exists dl_output_responses_public_insert on public.dl_output_responses;
create policy dl_output_responses_public_insert on public.dl_output_responses
  for insert to anon, authenticated
  with check (
    question_id is not null
    and exists (select 1 from public.dl_output_questions q where q.id = question_id)
    and char_length(name) between 1 and 100
    and char_length(answer) between 1 and 20000
    and char_length(coalesce(email, '')) <= 254
  );

-- 回答の読み出しはRPC dl_output_my_responses（名前＋メール一致）と
-- dl_output_admin_*（パスワード照合）経由のみ。anonからの直接SELECTは不可。
