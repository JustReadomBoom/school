/*
 * All rights Reserved, Copyright (C) Aisino LIMITED 2018
 * FileName: ListenerTest.java
 * Version:  $Revision$
 * Modify record:
 * NO. |     Date       |    Name        |      Content
 * 1   | 2019年1月16日        | Aisino)Jack    | original version
 */
package com.zqz.school.shiro;

import com.bskms.bean.User;
import com.bskms.mapper.UserMapper;
import com.bskms.mapper.UserRoleMapper;
import com.zqz.school.mapper.UserMapper;
import com.zqz.school.mapper.UserRoleMapper;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * class name: CustomRealm <BR>
 * class description: 自定义 Realm <BR>
 * 
 * @version 1.00 2019年1月16日
 * @author Aisino)weihaohao
 */
@Component
public class CustomRealm extends AuthorizingRealm {
	/** 用户信息service */
	private final UserMapper userMapper;
	/** 用户权限service */
	private final UserRoleMapper userRoleMapper;
	/** logback日志记录 */
	private final Logger logger = LoggerFactory.getLogger(CustomRealm.class);

	private static Map<String, Session> sessionMap = new HashMap<>();

	/**
	 * Method name: CustomRealm<BR>
	 * Description: 通过构造器注入Mapper<BR>
	 * 
	 * @param userMapper
	 * @param userRoleMapper <BR>
	 */
	@Autowired
	public CustomRealm(UserMapper userMapper, UserRoleMapper userRoleMapper) {
		this.userMapper = userMapper;
		this.userRoleMapper = userRoleMapper;
	}

	/**
	 * @Override
	 * @see org.apache.shiro.realm.AuthenticatingRealm#doGetAuthenticationInfo(AuthenticationToken)
	 *      <BR>
	 *      Method name: doGetAuthenticationInfo <BR>
	 *      获取身份验证信息 Description: Shiro中，最终是通过 Realm 来获取应用程序中的用户、角色及权限信息的。 <BR>
	 * @param authenticationToken 用户身份信息 token
	 * @return 返回封装了用户信息的 AuthenticationInfo 实例
	 * @throws AuthenticationException <BR>
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken)
			throws AuthenticationException {
		// 获取token令牌
		UsernamePasswordToken token = (UsernamePasswordToken) authenticationToken;
		// 从数据库获取对应用户名密码的用户
		User user = userMapper.selectByPrimaryKey(token.getUsername());
		if (null == user) {
			logger.warn("{}---用户不存在", token.getUsername());
			// 向前台抛出用户不存在json对象
			throw new AccountException("USERNAME_NOT_EXIST");
		}
		String password = user.getUserPassword();
		if (null == password) {
			logger.warn("{}---用户不存在", token.getUsername());
			// 向前台抛出用户不存在json对象
			throw new AccountException("USERNAME_NOT_EXIST");
		} else if (!password.equals(new String((char[]) token.getCredentials()))) {
			logger.warn("{}---输入密码错误", token.getUsername());
			// 向前台抛出输入密码错误json对象
			throw new AccountException("PASSWORD_ERR");
		}
		logger.info("{}---身份认证成功", user.getUserName());
		Subject subject = SecurityUtils.getSubject();
		// 设置shiro session过期时间(单位是毫秒!)
		subject.getSession().setTimeout(7_200_000);

		Session s = subject.getSession();
		String uid = user.getUserId();

		try {
			Session s2 = sessionMap.get(uid);
			if (s2 != null) {
				s2.setTimeout(0);
				sessionMap.remove(s2);
			}
		} catch (Exception e) {
			// 已经退出，但是还是有他。
			sessionMap.remove(s);
		}
		// 把这个人登录的信息给放进全局变量
		sessionMap.put(uid, s);

		return new SimpleAuthenticationInfo(user, password, getName());
	}

	/**
	 * @Override
	 * @see AuthorizingRealm#doGetAuthorizationInfo(PrincipalCollection)
	 *      <BR>
	 *      Method name: doGetAuthorizationInfo <BR>
	 *      Description: 获取授权信息 <BR>
	 * @param principalCollection
	 * @return <BR>
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
		// 从shro里面获取用户对象
		User user = (User) SecurityUtils.getSubject().getPrincipal();
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		// 角色列表
		List<String> roles = null;
		// 获得该用户角色
		if (null != user) {
			roles = userRoleMapper.getRoles(user.getUserId());
		} else {
			logger.warn("用户session失效!");
		}
		Set<String> set = new HashSet<>();
		// 需要将 role 封装到 Set 作为 info.setRoles() 的参数
		for (String role : roles) {
			set.add(role);
		}
		// 设置该用户拥有的角色
		info.setRoles(set);
		return info;
	}
}