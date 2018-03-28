package com.realm;

import org.apache.shiro.authc.*;
import org.apache.shiro.realm.AuthenticatingRealm;

/**
 * Created by Administrator on 2018/3/21 0021.
 */
public class UserRealm extends AuthenticatingRealm {

    //实现认证：判断是否登陆
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //得到用户输入的用户名
        String principal = (String) token.getPrincipal();//用户名
        char[] credentials = (char[]) token.getCredentials();//密码
        String pass = String.copyValueOf(credentials);

        //从数据库得到用户信息
        String dbUser = "qf";
        String dbPass = "qf";
        //是否从数据库中查到记录
        if (!pass.equals(dbPass)){
            throw new UnknownAccountException("用户或密码有误");

        }
        //认证信息返回
         String realmName = getName();//得到自定义的realm
        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(principal,credentials,realmName);
        return info;
    }
}
