import { NextRequest, NextResponse } from 'next/server';
import { createUser, createVerificationToken } from '@/lib/user-service';
import { sendEmail, generateVerificationEmailHtml } from '@/lib/email';
import { isValidEmail, hashPassword } from '@/lib/auth-utils';
import { db } from '@/lib/db';
import { users, userActivities } from '@/lib/schema';

// 发送验证邮件的通用函数
async function sendVerificationEmail(userEmail: string, locale: string) {
  try {
    console.log('开始发送验证邮件:', userEmail);
    
    // 生成邮箱验证令牌
    const verificationToken = await createVerificationToken(
      userEmail,
      'email_verification',
      24
    );

    if (!verificationToken) {
      console.error('生成验证令牌失败:', userEmail);
      return { success: false, error: '生成验证令牌失败' };
    }

    console.log('验证令牌生成成功:', verificationToken);

    // 发送验证邮件
    const verificationUrl = `${process.env.NEXTAUTH_URL}/${locale}/auth/verify-email?token=${verificationToken}`;
    console.log('验证链接:', verificationUrl);
    
    const emailHtml = generateVerificationEmailHtml(verificationUrl, locale);
    
    const emailResult = await sendEmail({
      to: userEmail,
      subject: locale === 'zh' ? 'Aiartools - 邮箱验证' : 'Aiartools - Email Verification',
      html: emailHtml,
    });

    if (!emailResult.success) {
      console.error('验证邮件发送失败:', userEmail, emailResult.error);
      return { success: false, error: emailResult.error };
    } else {
      console.log('验证邮件发送成功:', userEmail, emailResult.data);
      return { success: true, data: emailResult.data };
    }
  } catch (error) {
    console.error('发送验证邮件错误:', userEmail, error);
    return { success: false, error: error };
  }
}

export async function POST(request: NextRequest) {
  try {
    const { email, password, locale = 'zh' } = await request.json();

    // 验证输入
    if (!email || !password) {
      return NextResponse.json(
        { error: '邮箱和密码是必填项' },
        { status: 400 }
      );
    }

    if (!isValidEmail(email)) {
      return NextResponse.json(
        { error: '邮箱格式不正确' },
        { status: 400 }
      );
    }

    // 基本密码长度验证
    if (password.length < 6) {
      return NextResponse.json(
        { error: '密码长度至少需要6个字符' },
        { status: 400 }
      );
    }

    // 检查邮箱是否已经注册
    const existingUser = await db.query.users.findFirst({
      where: (users, { eq }) => eq(users.email, email.toLowerCase().trim())
    });

    if (existingUser) {
      if (existingUser.isEmailVerified) {
        return NextResponse.json(
          { error: '该邮箱已经注册并验证，请直接登录' },
          { status: 400 }
        );
      } else {
        // 重新发送验证邮件
        const emailResult = await sendVerificationEmail(existingUser.email, locale);
        
        if (emailResult.success) {
          return NextResponse.json(
            { message: '该邮箱已注册但未验证，已重新发送验证邮件，请检查邮箱' },
            { status: 200 }
          );
        } else {
          return NextResponse.json(
            { error: '该邮箱已注册但未验证，重新发送验证邮件失败，请稍后重试' },
            { status: 500 }
          );
        }
      }
    }

    // 创建新用户
    const hashedPassword = await hashPassword(password);
    
    const [newUser] = await db.insert(users).values({
      email: email.toLowerCase().trim(),
      password: hashedPassword,
      username: email.split('@')[0], // 默认用户名为邮箱前缀
      isEmailVerified: false,
      credits: 20, // 注册赠送20积分
    }).returning();

    if (!newUser) {
      return NextResponse.json(
        { error: '用户创建失败，邮箱可能已被注册' },
        { status: 400 }
      );
    }

    // 记录注册赠送积分的活动
    try {
      await db.insert(userActivities).values({
        userId: newUser.id,
        type: 'registration_bonus',
        description: 'credit_description.registration_bonus',
        creditAmount: 20,
        metadata: JSON.stringify({
          source: 'registration_bonus',
          email: newUser.email,
          type: 'registration_bonus',
        })
      });
    } catch (error) {
      console.error('记录注册积分活动失败:', error);
      // 不阻止注册流程，继续执行
    }

    // 立即返回成功响应，不等待邮件发送
    const response = NextResponse.json({
      message: 'Registration successful! Please check your email and click the verification link.',
      user: {
        id: newUser.id,
        email: newUser.email,
        username: newUser.username,
        isEmailVerified: newUser.isEmailVerified,
        credits: newUser.credits,
      },
    }, { status: 201 });

    // 异步发送验证邮件（不阻塞响应）
    Promise.resolve().then(async () => {
      await sendVerificationEmail(newUser.email, locale);
    }).catch((error) => {
      console.error('Promise异步执行错误:', error);
    });

    return response;
  } catch (error) {
    console.error('注册错误:', error);
    return NextResponse.json(
      { error: '服务器内部错误' },
      { status: 500 }
    );
  }
}