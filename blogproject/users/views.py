from django.shortcuts import render

# Create your views here.
# 注册视图
from django.views import View

from django.http.response import HttpResponseBadRequest
import re
from users.models import User
from django.db import DatabaseError
from django.shortcuts import redirect
from django.urls import reverse


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

            return HttpResponseBadRequest('注册失败')

        from django.contrib.auth import login
        login(request, user)

        response= redirect(reverse('home:index'))
        #4.返回响应，跳转到指定页面
        #return redirect(reverse('home:index'))
        #HttpResponse('注册成功，将跳转到首页')
        #设置cookkie信息，判断用户信息

        response.set_cookie('is_login',True)

        #用户信息的展示
        response.set_cookie('username',user.username,max_age=7*24*3600)
        return response


# 图片验证码
from libs.captcha.captcha import captcha
from django.http.response import HttpResponseBadRequest
from django_redis import get_redis_connection
from django.http import HttpResponse, response


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

        # 1.参数接收（查询字符串的形式传递过来）
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')


#18294202694
        # 2.参数的验证
        #  验证参数是否齐全
        redis_conn = get_redis_connection('default')
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






#登录实现
class LoginView(View):
    def get(self, request):
        return render(request, 'login.html')

    def post(self, request):
    # 1.接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
    # 2.参数的验证
    #     2.1 验证手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
    #     2.2 验证密码是否符合规则
        if not re.match(r'^[a-zA-Z0-9]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合规则')
    # 3.用户认证登录
    # 采用系统自带的认证方法进行认证
    # 如果我们的用户名和密码正确，会返回user
    # 如果我们的用户名或密码不正确，会返回None
        from django.contrib.auth import authenticate
    # 默认的认证方法是 针对于 username 字段进行用户名的判断
    # 当前的判断信息是 手机号，所以我们需要修改一下认证字段
    # 我们需要到User模型中进行修改，等测试出现问题的时候，我们再修改
        user = authenticate(mobile=mobile, password=password)

        if user is None:
                return HttpResponseBadRequest('用户名或密码错误')
    # 4.状态的保持
        from django.contrib.auth import login
        login(request, user)
    # 5.根据用户选择的是否记住登录状态来进行判断
    # 6.为了首页显示我们需要设置一些cookie信息

    # 根据next参数来进行页面的跳转
    #     next_page = request.GET.get('next')
    #     if next_page:
    #         response = redirect(next_page)
    #     else:
        response = redirect(reverse('home:index'))

        if remember != 'on':  # 没有记住用户信息
        # 浏览器关闭之后
            request.session.set_expiry(0)
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)
        else:  # 记住用户信息
        # 默认是记住 2周
            request.session.set_expiry(None)
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=14 * 24 * 3600)

    # 7.返回响应
        return response

#退出登录
from django.contrib.auth import logout
class LogoutView(View):
    def get(self, request):
        # 1.session数据清除
        logout(request)
        # 2.删除部分cookie数据
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')
        # 3.跳转到首页
        return response


#忘记密码
class ForgetPasswordView(View):

    def get(self,request):
        return render(request,'forget_password.html')

    def post(self, request):
        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #     2.1 判断参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('参数不全')
        #     2.2 手机号是否符合格则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合格则')
        #     2.3 判断密码是否符合格则
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合格则')
        #     2.4 判断确认密码和密码是否一致
        if password2 != password:
            return HttpResponseBadRequest('密码不一致')
        #     2.5 判断短信验证码是否正确
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if redis_sms_code.decode() != smscode:
            return HttpResponseBadRequest('短信验证码错误')
        # 3.根据手机号进行用户信息的查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 5.如果手机号没有查询出用户信息，则进行新用户的创建
            try:
                User.objects.create_user(username=mobile,
                                         mobile=mobile,
                                         password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 4.如果手机号查询出用户信息则进行用户密码的修改
            user.set_password(password)
            # 注意，保存用户信息
            user.save()

        # 6.进行页面跳转，跳转到登录页面
        response = redirect(reverse('users:login'))
        # 7.返回响应
        return response


from django.contrib.auth.mixins import LoginRequiredMixin


class UserCenterView(LoginRequiredMixin,View):
    def get(self,request):
        # 获得登录用户的信息
        user = request.user
        # 组织获取用户的信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc
        }
        return render(request, 'center.html', context=context)

    def post(self, request):
        """
        1.接收参数
        2.将参数保存起来
        3.更新cookie中的username信息
        4.刷新当前页面（重定向操作）
        5.返回响应
        :param request:
        :return:
        """
        user = request.user
        # 1.接收参数
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)
        avatar = request.FILES.get('avatar')
        # 2.将参数保存起来
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('修改失败，请稍后再试')
        # 3.更新cookie中的username信息
        # 4.刷新当前页面（重定向操作）
        response = redirect(reverse('users:center'))
        response.set_cookie('username', user.username, max_age=14 * 3600 * 24)

        # 5.返回响应
        return response

from home.models import ArticleCategory,Article
class WriteBlogView(LoginRequiredMixin,View):

    def get(self,request):
        #查询所有分类模型
        categories=ArticleCategory.objects.all()

        context = {
            'categories':categories
        }
        return render(request,'write_blog.html',context=context)

    def post(self,request):

        # 1.接收数据
        avatar=request.FILES.get('avatar')
        title=request.POST.get('title')
        category_id=request.POST.get('category')
        tags=request.POST.get('tags')
        sumary=request.POST.get('sumary')
        content=request.POST.get('content')
        user=request.user

        # 2.验证数据
        # 2.1 验证参数是否齐全
        if not all([avatar,title,category_id,sumary,content]):
            return HttpResponseBadRequest('参数不全')
        # 2.2 判断分类id
        try:
            category=ArticleCategory.objects.get(id=category_id)
        except ArticleCategory.DoesNotExist:
            return HttpResponseBadRequest('没有此分类')
        # 3.数据入库
        try:
            article=Article.objects.create(
                author=user,
                avatar=avatar,
                title=title,
                category=category,
                tags=tags,
                sumary=sumary,
                content=content
            )
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('发布失败，请稍后再试')
        # 4.跳转到指定页面（暂时首页）
        return redirect(reverse('home:index'))





