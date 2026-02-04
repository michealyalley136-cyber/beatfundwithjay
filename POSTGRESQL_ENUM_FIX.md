# PostgreSQL Enum Type Casting Fix

## Issue
Production errors on `/api/notifications/unread-count` and similar endpoints:

```
sqlalchemy.exc.ProgrammingError: (psycopg.errors.UndefinedFunction) operator does not exist: "RoleEnum" <> character varying
```

## Root Cause
The `User.role` column is defined as `db.String(40)` in the database (VARCHAR), but the code was comparing it directly with Python enum objects (`RoleEnum.admin`) instead of the string values.

When SQLAlchemy generates SQL for a query like:
```python
.filter(User.role != RoleEnum.admin)
```

It passes the enum object as a parameter, and PostgreSQL tries to compare:
```sql
"user".role != $2::VARCHAR  (where $2 is RoleEnum.admin object)
```

Since `role` is stored as VARCHAR but the comparison parameter is a RoleEnum type, PostgreSQL can't find an appropriate operator and throws an error.

## Solution
Changed all database filter comparisons to use the string value of the enum:

```python
# Before (ERROR)
.filter(User.role != RoleEnum.admin)

# After (FIXED)
.filter(User.role != RoleEnum.admin.value)
```

## Files Modified
- **app.py**: Fixed 8 locations where `User.role` was compared with `RoleEnum` enum objects in database queries

## Locations Fixed

| Line | Endpoint/Function | Change |
|------|-------------------|--------|
| 9918 | `get_notifications` (legacy) | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |
| 10029 | `/api/notifications/unread-count` | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |
| 10048 | `/api/notifications/recent` | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |
| 10107 | (Continuation of above) | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |
| 10232 | `/dashboard/admin` | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |
| 10668 | `/superadmin` | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |
| 13612 | Admin user search | `== RoleEnum(role)` → `== RoleEnum(role).value` |
| 14717 | `/admin/reports` | `!= RoleEnum.admin` → `!= RoleEnum.admin.value` |

## Why This Matters
- **String enums in SQLAlchemy**: When a database column is `VARCHAR`, it must be compared with string values
- **Python enums**: While Python enums can be used in application logic, they need `.value` to get the string representation for database comparisons
- **Type safety**: PostgreSQL is strict about type matching in SQL comparisons

## Testing
All affected endpoints should now:
- ✅ Query without database errors
- ✅ Correctly filter out admin users from notification queries
- ✅ Display accurate user counts in admin dashboards
- ✅ Filter users by role in search endpoints

## Affected Features
1. **Notification API** - `/api/notifications/unread-count`, `/api/notifications/recent`
2. **Admin Dashboard** - User count displays
3. **Superadmin Panel** - User statistics
4. **User Search** - Role filtering
5. **Reports** - Role-based analytics
