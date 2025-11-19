# 1. نختار صورة بايثون "خفيفة" وسريعة كأساس
FROM python:3.9-slim

# 2. نحدد مجلد العمل داخل الحاوية (Container)
WORKDIR /app

# 3. ننسخ ملف المتطلبات أولاً (عشان نستفيد من الكاش حق Docker)
COPY requirements.txt .

# 4. نثبت المكتبات المطلوبة
RUN pip install --no-cache-dir -r requirements.txt

# 5. ننسخ باقي ملفات المشروع (app.py ومجلد templates)
COPY . .

# 6. نفتح البورت 5001 (نفس البورت اللي نستخدمه في الكود)
EXPOSE 5001

# 7. أمر تشغيل التطبيق
CMD ["python", "app.py"]