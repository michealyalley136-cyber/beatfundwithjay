# Deploying BeatFund to Render.com

This guide will help you deploy the BeatFund application to Render.com.

## Prerequisites

1. A GitHub account with your code pushed to a repository
2. A Render.com account (sign up at https://render.com)

## Deployment Steps

### Option 1: Using render.yaml (Recommended)

1. **Push your code to GitHub** (if not already done)
   ```bash
   git add .
   git commit -m "Prepare for Render deployment"
   git push origin main
   ```

2. **Connect to Render**
   - Go to https://dashboard.render.com
   - Click "New +" → "Blueprint"
   - Connect your GitHub repository
   - Render will automatically detect `render.yaml` and create the services

3. **Environment Variables**
   - Render will automatically:
     - Set `APP_ENV=prod`
     - Generate a `SECRET_KEY`
     - Connect to the PostgreSQL database
     - Set `PORT=10000`

4. **Database Setup**
   - After deployment, you'll need to run migrations:
     - Go to your web service → Shell
     - Run: `python migrate_multi_role.py` (if needed)
     - Or set `BOOTSTRAP_DB=1` temporarily to create tables

### Option 2: Manual Setup

1. **Create PostgreSQL Database**
   - Go to Render Dashboard → "New +" → "PostgreSQL"
   - Name: `beatfund-db`
   - Plan: Free (or paid for production)
   - Copy the "Internal Database URL"

2. **Create Web Service**
   - Go to "New +" → "Web Service"
   - Connect your GitHub repository
   - Settings:
     - **Name**: `beatfund`
     - **Environment**: `Python 3`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `gunicorn --bind 0.0.0.0:$PORT app:app`
     - **Plan**: Free (or paid for production)

3. **Environment Variables**
   Add these in the "Environment" section:
   ```
   APP_ENV=prod
   SECRET_KEY=<generate a strong random key>
   DATABASE_URL=<from your PostgreSQL service>
   PORT=10000
   ```

4. **Deploy**
   - Click "Create Web Service"
   - Render will build and deploy your app

## Post-Deployment Setup

### 1. Initialize Database

After first deployment, initialize the database:

**Option A: Using Shell**
- Go to your web service → Shell
- Run: `python -c "from app import app, db; app.app_context().push(); db.create_all()"`

**Option B: Using Environment Variable**
- Add `BOOTSTRAP_DB=1` to environment variables
- Redeploy (this will create all tables)
- Remove `BOOTSTRAP_DB=1` after first run

### 2. Run Migrations

If you have existing migrations:
```bash
# In Render Shell
python migrate_multi_role.py
python migrate_vault_lock.py
```

### 3. Create Admin User

```bash
# In Render Shell
python create_admin.py
```

## Environment Variables Reference

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `APP_ENV` | Yes | Environment mode | `prod` |
| `SECRET_KEY` | Yes | Flask secret key | (auto-generated) |
| `DATABASE_URL` | Yes | PostgreSQL connection | (auto-set by Render) |
| `PORT` | Yes | Server port | `10000` |
| `BOOTSTRAP_DB` | No | Create tables on startup | `1` (one-time) |

## File Uploads

Render's filesystem is ephemeral. For production, consider:

1. **Use a cloud storage service** (AWS S3, Cloudinary, etc.)
2. **Update upload paths** in `app.py` to use cloud storage
3. **Or use Render Disk** (paid feature) for persistent storage

## Static Files

Static files are served automatically by Flask in development. For production:

- Consider using a CDN (Cloudflare, etc.)
- Or configure Flask to serve static files efficiently
- Current setup should work for small to medium traffic

## Monitoring

- Check logs in Render Dashboard → Your Service → Logs
- Set up health checks (already configured in render.yaml)
- Monitor database connections and performance

## Troubleshooting

### Database Connection Issues
- Verify `DATABASE_URL` is set correctly
- Check database is running
- Ensure connection string uses `postgresql://` (not `postgres://`)

### Build Failures
- Check `requirements.txt` is up to date
- Verify Python version in `runtime.txt` matches Render's support
- Check build logs for specific errors

### App Not Starting
- Check start command in Procfile
- Verify PORT environment variable
- Check application logs for errors

### Static Files Not Loading
- Verify static files are committed to git
- Check file paths in templates
- Ensure `static/` folder structure is correct

## Updating Your App

1. Push changes to GitHub
2. Render automatically detects and redeploys
3. Or manually trigger deployment in Render Dashboard

## Security Notes

- Never commit `SECRET_KEY` to git
- Use Render's environment variables for secrets
- Enable HTTPS (automatic on Render)
- Review and update security settings in `app.py`

## Support

- Render Docs: https://render.com/docs
- Render Community: https://community.render.com

