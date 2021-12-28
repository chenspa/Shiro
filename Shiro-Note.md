# Shiro

## 一、官方文档
`https://shiro.apache.org/documentation.html`

## 二、环境
~~~
<!--        引入shiro-->
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-core</artifactId>
    <version>1.7.1</version>
</dependency>

~~~

## 三、shiro 认证

 - 1、 MD5 的实现

`CustomerMd5Realm`
~~~
public class CustomerMd5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = (String) authenticationToken.getPrincipal();
        if ("root".equals(principal)) {
            return new SimpleAuthenticationInfo(principal, "e10adc3949ba59abbe56e057f20f883e", this.getName());
        }

        return null;
    }
}

~~~

`TestCustomerMd5RealmAuthenticator`
~~~
public class TestCustomerMd5RealmAuthenticator {
    public static void main(String[] args) {
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        CustomerMd5Realm realm = new CustomerMd5Realm();

        /**
            设置 realm 使用 hash 凭证匹配器
        */
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        realm.setCredentialsMatcher(credentialsMatcher);

        defaultSecurityManager.setRealm(realm);
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("root", "123456");

        try {
            subject.login(usernamePasswordToken);
            System.out.println("登录成功！");
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("用户名错误!");
        } catch (IncorrectCredentialsException e) {
            System.out.println("登录错误！");
        }

    }
}

~~~

 - 2、 MD5 + salt 的实现

`CustomerMd5Realm`
~~~
public class CustomerMd5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = (String) authenticationToken.getPrincipal();
        if ("root".equals(principal)) {
            return new SimpleAuthenticationInfo(principal,
                    "e99a0dee78d3c1f71609cead42047675",
                    ByteSource.Util.bytes("X0*7ps"),
                    this.getName());
        }

        return null;
    }
}

~~~

`TestCustomerMd5RealmAuthenticator`
~~~
public class TestCustomerMd5RealmAuthenticator {
    public static void main(String[] args) {
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        CustomerMd5Realm realm = new CustomerMd5Realm();

        /**
            设置 realm 使用 hash 凭证匹配器
        */
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        realm.setCredentialsMatcher(credentialsMatcher);

        defaultSecurityManager.setRealm(realm);
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("root", "123456");

        try {
            subject.login(usernamePasswordToken);
            System.out.println("登录成功！");
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("用户名错误!");
        } catch (IncorrectCredentialsException e) {
            System.out.println("登录错误！");
        }

    }
}

~~~


 - 3、 MD5 + salt 1024次散列的实现

`CustomerMd5Realm`
~~~
public class CustomerMd5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        return null;
    }

    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = (String) authenticationToken.getPrincipal();
        if ("root".equals(principal)) {
            return new SimpleAuthenticationInfo(principal,
                    "e99a0dee78d3c1f71609cead42047675",
                    ByteSource.Util.bytes("X0*7ps"),
                    this.getName());
        }

        return null;
    }
}

~~~

`TestCustomerMd5RealmAuthenticator`
~~~
public class TestCustomerMd5RealmAuthenticator {
    public static void main(String[] args) {
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        CustomerMd5Realm realm = new CustomerMd5Realm();

        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(1024);
        realm.setCredentialsMatcher(credentialsMatcher);

        defaultSecurityManager.setRealm(realm);
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("root", "123456");

        try {
            subject.login(usernamePasswordToken);
            System.out.println("登录成功！");
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("用户名错误!");
        } catch (IncorrectCredentialsException e) {
            System.out.println("登录错误！");
        }

    }
}

~~~


## 四、shiro 授权

`CustomerMd5Realm`
~~~
public class CustomerMd5Realm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("==============");
        String primaryPrincipal = (String) principalCollection.getPrimaryPrincipal();
        System.out.println("身份信息： " + primaryPrincipal);

        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        simpleAuthorizationInfo.addRole("admin");
        simpleAuthorizationInfo.addRole("user");

        simpleAuthorizationInfo.addStringPermission("user:*:01");
        simpleAuthorizationInfo.addStringPermission("product:create");

        return simpleAuthorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        String principal = (String) authenticationToken.getPrincipal();
        if ("root".equals(principal)) {
            return new SimpleAuthenticationInfo(principal,
                    "955224a95d4161ad8bd84f7ede979c02",
                    ByteSource.Util.bytes("X0*7ps"),
                    this.getName());
        }

        return null;
    }
}


~~~

`TestCustomerMd5RealmAuthenticator`
~~~
public class TestCustomerMd5RealmAuthenticator {
    public static void main(String[] args) {
        DefaultSecurityManager defaultSecurityManager = new DefaultSecurityManager();
        CustomerMd5Realm realm = new CustomerMd5Realm();

        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        credentialsMatcher.setHashAlgorithmName("md5");
        credentialsMatcher.setHashIterations(1024);
        realm.setCredentialsMatcher(credentialsMatcher);

        defaultSecurityManager.setRealm(realm);
        SecurityUtils.setSecurityManager(defaultSecurityManager);
        Subject subject = SecurityUtils.getSubject();

        /*
        认证
         */
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken("root", "123456");

        try {
            subject.login(usernamePasswordToken);
            System.out.println("登录成功！");
        } catch (UnknownAccountException e) {
            e.printStackTrace();
            System.out.println("用户名错误!");
        } catch (IncorrectCredentialsException e) {
            System.out.println("登录错误！");
        }

        /*
        授权
         */
        if (subject.isAuthenticated()) {
            System.out.println(subject.hasRole("user"));
            System.out.println(subject.hasAllRoles(Arrays.asList("admin", "user")));

            boolean[] booleans = subject.hasRoles(Arrays.asList("admin", "super", "user"));
            for (boolean aBoolean : booleans) {
                System.out.println(aBoolean);
            }

            System.out.println("----------=========------------");
            System.out.println("权限：" + subject.isPermitted("user:update:01"));
            System.out.println("权限：" + subject.isPermitted("product:create:02"));

            /*
            分别具有权限
             */
            boolean[] permitted = subject.isPermitted("user:*:01", "order:*:10");
            for (boolean b : permitted) {
                System.out.println(b);
            }
            /*
            同时具有权限
             */
            boolean permittedAll = subject.isPermittedAll("user:*:01", "product:*");
            System.out.println(permittedAll);

        }
    }
}

~~~


## 五、整合SpringBoot项目实战

