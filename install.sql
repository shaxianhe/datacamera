drop table if exists user_pwd_camera;
create table user_pwd_camera(username varchar(9) not null,password varchar(25) not null,cid varchar(25),primary key(username));
drop table if exists camera;
create table camera (cid varchar(25) not null,primary key(cid));
