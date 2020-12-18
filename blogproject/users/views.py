from django.shortcuts import render

# Create your views here.
# 注册视图
from django.views import View

from django.http.response import HttpResponseBadRequest
import re
from users.models import User
from django.db import DatabaseError


class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self,request):

        #1.接收数据

        mobile=request.POST.get('mobile')
        password=request.POST.get('password')
        password2=request.POST.get('password2')
        smscode=request.POST.get('sms_code')

        #2.验证数据
            #验证参数是否齐全
        if not all([mobile,password,password2,smscode]):
            return HttpResponseBadRequest('缺少必要是参数')
            #手机号格式
            if not re.match(r'^1[3-9]\d{9}$',mobile):
             return HttpResponseBadRequest('手机号不符合规则')
            #密码是否一致
            if not re.match(r'[0-9A-Za-z]{8,20}$',password):
                return HttpResponseBadRequest('密码强度太弱')
            if password != password2:
                return HttpResponseBadRequest('两次密码不一致')
            #短信验证码是否和redis中一致
            redis_conn=get_redis_connection('default')
            redis_sms_code=redis_conn.get('sms:%s' % mobile)
            if redis_sms_code is None:
                return HttpResponseBadRequest('短信验证码已过期')
            if smscode != redis_sms_code.decode():
                return HttpResponseBadRequest('短信验证码不一致')
        #3.保存数据
        try:
            user =User.objects.create_user(
            username=mobile,
            mobile=mobile,
            password=password
        )
        except DatabaseError as e:
            logger.error(e)
         #   return HttpResponseBadRequest('注册失败')
        #4.返回响应，跳转到指定页面

        return redirect(reverse('home:index'))#HttpResponse('注册成功，将跳转到首页')


# 图片验证码
from libs.captcha.captcha import captcha
from django.http.response import HttpResponseBadRequest
from django_redis import get_redis_connection
from django.http import HttpResponse


class ImageCodeView(View):
    def get(self, request):
        # 1.接收前端传递的uuid
        uuid = request.GET.get('uuid')
        # 2.判断uuid是否获取到
        if uuid is None:
            return HttpResponseBadRequest('没有传递uuid')
        # 3.通过调用captch来生成图片验证码
        text, image = captcha.generate_captcha()
        # 4.将图片内容保存到redis0号库中
        redis_conn = get_redis_connection('default')
        # 5.uuid作为一个key，图片内容作为一个value，同时设置一个时效

        # redis_conn.setex(key, seconds, value)
        # key设置为uuid
        # seconds验证码过期秒数
        # value text 为captcha生成的图片二进制

        redis_conn.setex(' img:%s' % uuid, 200, text)
        # 6.返回图片二进制
        return HttpResponse(image, content_type='image/jpeg')


# 短信验证码
from django.http.response import JsonResponse
from utils.response_code import RETCODE
import logging

logger = logging.getLogger('django')
from random import randint
from libs.yuntongxun.sms import CCP


class SmsCodeView(View):
    def get(self, request):
        redis_conn = get_redis_connection('default')
        # 1.参数接收（查询字符串的形式传递过来）
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')



        # 2.参数的验证
        #  验证参数是否齐全
        if not all([mobile, image_code, uuid]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少是参数'})
            # 连接redis，获取redis中的图片验证码

            redis_image_code = redis_conn.get('img:%s' % uuid)
             # 判断图片验证码是否存在
            if redis_image_code is None:
                return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码已过期'})
            # 如果图片验证码未过期，获取到验证码之后就可以删除图片验证码
            try:
                redis_conn.delete('img:%s' % uuid)
            except Exception as e:
                logger.error(e)

            # 对比图片验证码(注意大小写)
            if redis_image_code.decode().lower() != image_code.lower():
                return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码错误'})




        # 3.生成短信验证码
        sms_code = '%06d' % randint(0, 999999)
        # 为了比对方便，可以记录日志
        logger.info(sms_code)
        # 4.保存短信验证码到redis中
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        # 5.发送短信
        CCP().send_template_sms(mobile, [sms_code, 5], 1)
        # 6. 返回响应
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功'})
# jxg419111582
