-- Read-only check for your OTHER Supabase project (NOT fstvghnkdgtmliqjyxpg). Changes nothing.
-- Shows the columns of its "students" table, in the order they were created.
select column_name, data_type, ordinal_position
from information_schema.columns
where table_schema = 'public' and table_name = 'students'
order by ordinal_position;
