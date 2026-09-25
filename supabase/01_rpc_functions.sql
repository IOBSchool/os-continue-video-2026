-- Daily Letters（OS継続コース）アウトプットページ セキュリティ設計
-- STEP 1: DL専用テーブルとRPC関数を作る（B社の output_* テーブルには一切触れない）
--
-- 設計方針（B社のアウトプット月間ページと同じSupabaseプロジェクトだがDL専用に完全分離）:
--   - テーブルは dl_ 接頭辞（dl_output_questions / dl_output_responses）
--   - B社と違い、回答者は「個人」なので「部署名」列は持たない（お名前＋メールのみ）
--   - 管理パスワードは平文で置かず、bcryptハッシュだけを非公開スキーマ private に保存
--   - __DL_ADMIN_HASH__ は実ハッシュに置き換えて実行（ハッシュ自体はリポにコミットしない）
--     ハッシュ生成: select extensions.crypt('決めたパスワード', extensions.gen_salt('bf'));

-- ===== テーブル =====
create table if not exists public.dl_output_questions (
  id          uuid primary key default gen_random_uuid(),
  month_label text not null default '',
  week_number int  not null default 1,
  start_date  date not null,
  end_date    date not null,
  theme       text not null default '',
  question    text not null,
  description  text not null default '',
  created_at  timestamptz not null default now()
);

create table if not exists public.dl_output_responses (
  id            uuid primary key default gen_random_uuid(),
  question_id   uuid not null references public.dl_output_questions(id) on delete cascade,
  question_text text not null default '',
  month_label   text not null default '',
  week_number   int  not null default 1,
  theme         text not null default '',
  name          text not null,
  email         text not null default '',
  answer        text not null,
  created_at    timestamptz not null default now()
);
create index if not exists dl_output_responses_lookup
  on public.dl_output_responses (lower(email), name);

-- ===== 管理パスワード（非公開スキーマ private に bcrypt ハッシュだけ保存）=====
create schema if not exists private;
revoke all on schema private from public, anon, authenticated;

create table if not exists private.dl_output_admin_secret (
  id int primary key default 1 check (id = 1),
  pw_hash text not null
);
revoke all on private.dl_output_admin_secret from public, anon, authenticated;
insert into private.dl_output_admin_secret (id, pw_hash) values (1, '__DL_ADMIN_HASH__')
  on conflict (id) do update set pw_hash = excluded.pw_hash;

-- パスワード照合（内部用・APIには出さない）
create or replace function private.dl_output_admin_ok(p_pw text)
returns boolean language sql stable security definer set search_path = '' as $$
  select coalesce(
    (select s.pw_hash = extensions.crypt(coalesce(p_pw, ''), s.pw_hash)
       from private.dl_output_admin_secret s where s.id = 1), false);
$$;
revoke all on function private.dl_output_admin_ok(text) from public, anon, authenticated;

create or replace function private.dl_output_admin_assert(p_pw text)
returns void language plpgsql stable security definer set search_path = '' as $$
begin
  if not private.dl_output_admin_ok(p_pw) then
    raise exception 'unauthorized' using errcode = '42501';
  end if;
end $$;
revoke all on function private.dl_output_admin_assert(text) from public, anon, authenticated;

-- ===== マイページ: 名前＋メールが両方一致した回答だけ返す =====
create or replace function public.dl_output_my_responses(p_name text, p_email text)
returns table (id uuid, week_number int, month_label text, theme text, question_text text,
               answer text, created_at timestamptz)
language sql stable security definer set search_path = '' as $$
  select r.id, r.week_number, r.month_label, r.theme, r.question_text, r.answer, r.created_at
    from public.dl_output_responses r
   where length(trim(coalesce(p_name, ''))) > 0
     and length(trim(coalesce(p_email, ''))) > 0
     and r.name = trim(p_name)
     and lower(r.email) = lower(trim(p_email))
   order by r.created_at desc;
$$;

-- ===== 管理画面 =====
create or replace function public.dl_output_admin_login(p_pw text)
returns boolean language sql stable security definer set search_path = '' as $$
  select private.dl_output_admin_ok(p_pw);
$$;

create or replace function public.dl_output_admin_insert_question(p_pw text, p_row jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.dl_output_admin_assert(p_pw);
  insert into public.dl_output_questions (month_label, week_number, start_date, end_date, theme, question, description)
  values (coalesce(p_row->>'month_label', ''), coalesce((p_row->>'week_number')::int, 1),
          (p_row->>'start_date')::date, (p_row->>'end_date')::date,
          coalesce(p_row->>'theme', ''), p_row->>'question', coalesce(p_row->>'description', ''));
end $$;

create or replace function public.dl_output_admin_update_question(p_pw text, p_id uuid, p_row jsonb)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.dl_output_admin_assert(p_pw);
  update public.dl_output_questions set
    month_label = coalesce(p_row->>'month_label', ''),
    week_number = coalesce((p_row->>'week_number')::int, 1),
    start_date  = (p_row->>'start_date')::date,
    end_date    = (p_row->>'end_date')::date,
    theme       = coalesce(p_row->>'theme', ''),
    question    = p_row->>'question',
    description  = coalesce(p_row->>'description', '')
  where id = p_id;
end $$;

create or replace function public.dl_output_admin_delete_question(p_pw text, p_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.dl_output_admin_assert(p_pw);
  delete from public.dl_output_questions where id = p_id;
end $$;

create or replace function public.dl_output_admin_list_responses(p_pw text, p_question_id uuid default null)
returns setof public.dl_output_responses language plpgsql stable security definer set search_path = '' as $$
begin
  perform private.dl_output_admin_assert(p_pw);
  return query
    select * from public.dl_output_responses r
     where (p_question_id is null or r.question_id = p_question_id)
     order by r.created_at desc;
end $$;

create or replace function public.dl_output_admin_delete_response(p_pw text, p_id uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
  perform private.dl_output_admin_assert(p_pw);
  delete from public.dl_output_responses where id = p_id;
end $$;

-- 実行権限: 既定の PUBLIC 付与を外し、anon/authenticated にだけ明示付与
do $$
declare f text;
begin
  foreach f in array array[
    'public.dl_output_my_responses(text,text)',
    'public.dl_output_admin_login(text)',
    'public.dl_output_admin_insert_question(text,jsonb)',
    'public.dl_output_admin_update_question(text,uuid,jsonb)',
    'public.dl_output_admin_delete_question(text,uuid)',
    'public.dl_output_admin_list_responses(text,uuid)',
    'public.dl_output_admin_delete_response(text,uuid)'
  ] loop
    execute format('revoke all on function %s from public', f);
    execute format('grant execute on function %s to anon, authenticated', f);
  end loop;
end $$;

notify pgrst, 'reload schema';
