FROM python:3.11-slim

# تعطيل كتابة ملفات pycache داخل الحاوية
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# إنشاء مجلد العمل
WORKDIR /app

# تثبيت SQLite (لأن قاعدة البيانات ستُستخدم)
RUN apt-get update && apt-get install -y sqlite3 && rm -rf /var/lib/apt/lists/*

# نسخ ملف المتطلبات أولاً للاستفادة من caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# نسخ باقي ملفات المشروع
COPY . .

# إنشاء مجلد لقاعدة البيانات وجعله قابل للكتابة
RUN mkdir -p /app/data && chmod 777 /app/data

# تغيير مسار قاعدة البيانات إلى مجلد data (حيث أنه دائم على Railway)
ENV DATABASE_PATH=/app/data/fingerprints.db

# فتح المنفذ
EXPOSE 5000

# تشغيل التطبيق باستخدام Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
