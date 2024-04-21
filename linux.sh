#!/bin/bash

#打印banner
function Banner(){
    echo "
    ___________                                                                
    \_   _____/ _____   ___________  ____   ____   ____   ____ ___.__.         
    |    __)_ /     \_/ __ \_  __ \/ ___\_/ __ \ /    \_/ ___<   |  |  ______ 
    |        \  Y Y  \  ___/|  | \/ /_/  >  ___/|   |  \  \___\___  | /_____/ 
    /_______  /__|_|  /\___  >__|  \___  / \___  >___|  /\___  > ____|         
            \/      \/     \/     /_____/      \/     \/     \/\/              
    .____    .__                     
    |    |   |__| ____  __ _____  ___
    |    |   |  |/    \|  |  \  \/  /
    |    |___|  |   |  \  |  />    < 
    |_______ \__|___|  /____//__/\_ \\
            \/       \/            \/                                 

    "
    }

function Basic_Info(){
    echo "===============基本信息============"
    echo "主机名:$(hostname)"
    echo "当前用户:$(whoami)"
    echo "查看当前登录用户"
    w
    echo "=================end=============="
}
function bprintf(){
    len=${#1}
    len=$(((64-$len)/2))
    printf '=%.0s' $(seq $len)
    printf '%s' $1
    printf '=%.0s' $(seq $len)
    printf '\n'

}

Command_Exist(){
    if command -v $1 >/dev/null 2>&1; then
        echo 1
    else
        echo 0
    fi
}
Evil_Process(){
    bprintf "占用前三的进程"
    ps aux  --sort=-%cpu | head -n 4
}
#入侵排查
Invade_Identify(){
    bprintf "入侵检测"
    echo  "特权用户:"
    awk -F: '$3==0{print $1}' /etc/passwd
    echo "可登录用户"
    awk -F: '$NF!="/usr/sbin/nologin"{print $1}' /etc/passwd |paste -sd ','
    echo "可以远程登录的账号信息"
    awk '/\$1|\$6/{print $1}' /etc/shadow
    echo "存在sudo权限的账号"
    cat /etc/sudoers | grep -v "^#\|^$" | grep "ALL=(ALL)\|ALL=(ALL:ALL)"
    bprintf "历史命令"
    user_list=$(ls /home)

    for user in $user_list
    do
        echo "$user用户可疑命令:"
        grep -e "bash" -e "wget" -e "ssh" /home/$user/.bash_history 2>/dev/null
        echo "$user用户最近登录信息:"
        last $user
    done

    bprintf "建立连接的IP地址"

    info=$(ss -an |grep "tcp\|udp")
    echo "$info" 
    ports=$(echo "$info" |awk '{print $5}' |awk -F ':' '{print $2}' |sort |uniq )
    for port in $ports;do
        echo "端口$port启动信息"
        lsof -i :$port
    done


    bprintf "开机启动配置文件"
    cat /etc/rc.local
    cat /etc/rc.d/rc[0~6].d 2>/dev/null

    bprintf "计划任务"
    for user in $user_list
    do
        echo "$user用户计划任务:"
        crontab -u $user -l
    done
    bprintf "可疑计划任务文件"
    a="/var/spool/cron/* 
    /etc/crontab
    /etc/cron.d/*
    /etc/cron.daily/* 
    /etc/cron.hourly/* 
    /etc/cron.monthly/*
    /etc/cron.weekly/
    /etc/anacrontab
    /var/spool/anacron/*"
    for dir in $a
    do
        ls $dir 2>/dev/null
    done

    bprintf "查看所有服务"
    service --status-all 2>/dev/null

    
    bprintf "7天内修改过的系统文件"
    find /usr/bin /usr/sbin /bin /usr/local/bin -type f -mtime -7 -exec ls -lt {} +
    

    
}
#后门检查
BackDoor_Identify(){
    bprintf "后门检查"
    user_list=$(ls /home)
    for user in $user_list
    do  
        if [[ -e "/home/$user/authorized_keys" ]];then
            bprintf "ssh公私钥免密登录"
            echo "$user用户 authorized_keys"文件存在,修改时间 $(ls -l /home/$user/authorized_keys |awk '{print $6,$7,$8}')

        else
            :
        fi
    done
    
    backdoor_of_alias=$(alias|grep "ssh='strace")
    if [ -n "$backdoor_of_alias" ];then 
        echo "----------------------------------"
        echo "发现疑似alias后门 $backdoor_of_alias"
    else
        :
    fi





}
Log_Analysis(){
    Log_Base="/var/log"
    #得到一个日志文件列表
    Log_list=$(ls $Log_Base |awk -F. '{print $1}' |uniq)
    for Log_type in $Log_list
    do 
    eval "Log_Of_$Log_type" 2>/dev/null
    done

}
function Log_Of_auth(){
    pattern=${1:-"/var/log/auth.*"}
    files=$(ls -t $pattern)
    for file in $files
    do 
        if [ "${file##*.}" = "gz" ]; then
            :
        else
            echo "$file文件分析:"
            #ssh爆破失败
            failure=$(grep --text "authentication failure" $file)
            users=$(echo "$failure" |grep -oP 'user=\K\S+' |sort|uniq)
            ips=$(echo "$failure" |grep -oP 'rhost=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            echo "用户名    失败次数:"
            for user in $users
            do 
                u=$(echo "$failure" |grep "user=$user")
                i=$(echo "$u" |wc -l)
                echo -n $user "     "
                echo  $i
                echo "爆破的IP"
                echo -n  "$u" | grep -oP 'rhost=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | uniq |awk -F '=' '{print $2}'
            
                echo '----------------------'
            done

            #ssh成功登录
            echo "登录成功记录"
            success=$(grep --text "Accepted password " $file)
            # echo "$success"
            time_user_ip=$(echo "$success" |awk '{print $1,$2,$3,$9,$11}')
            echo "$time_user_ip"
            echo "----------------------"

            echo "爆破用户名字典"
            grep -a "Failed password" $file| perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|sort| uniq -c

            echo "sudo命令执行历史"
            sudo_history=$(grep "sudo:" $file |grep "COMMAND")
            echo "$sudo_history" |head
            
        fi
    done
}
function Log_Of_apache2(){
    #access.log文件分析
    pattern=${1:-"/var/log/apache2/access*"}
    files=$(ls -t $pattern)
    for file in $files
    do 
        if [ "${file##*.}" = "gz" ]; then
            :
        else
            echo "$file文件分析:"
            ips=$(cat $file |awk  '{print $1}' |uniq)
            for ip in $ips
                do
                echo "$ip行为分析:" 
                echo "状态码 次数"
                cat "$file" |grep ^$ip |awk '{print $9}' |sort |uniq -c |awk '{print $2 "    " $1}'


                done
        fi
    done

    #error.log分析

}
function Log_Of_secure(){
    pattern=${1:-"/var/log/secure"}
    files=$(ls -t $pattern)
    for file in $files
    do 
        if [ "${file##*.}" = "gz" ]; then
            :
        else
            echo "$file文件分析:"
            #ssh爆破失败
            failure=$(grep --text "authentication failure" $file)
            users=$(echo "$failure" |grep -oP 'user=\K\S+' |sort|uniq)
            ips=$(echo "$failure" |grep -oP 'rhost=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
            echo "用户名    失败次数:"
            for user in $users
            do 
                u=$(echo "$failure" |grep "user=$user")
                i=$(echo "$u" |wc -l)
                echo -n $user "     "
                echo  $i
                echo "爆破的IP"
                echo -n  "$u" | grep -oP 'rhost=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | uniq |awk -F '=' '{print $2}'
            
                echo '----------------------'
            done

            #ssh成功登录
            echo "登录成功记录"
            success=$(grep --text "Accepted password " $file)
            # echo "$success"
            time_user_ip=$(echo "$success" |awk '{print $1,$2,$3,$9,$11}')
            echo "$time_user_ip"
            echo "----------------------"

            echo "爆破用户名字典"
            grep -a "Failed password" $file| perl -e 'while($_=<>){ /for(.*?) from/; print "$1\n";}'|sort| uniq -c

            echo "sudo命令执行历史"
            sudo_history=$(grep "sudo:" $file |grep "COMMAND")
            echo "$sudo_history" |head
            
        fi
    done
}


function webshell(){
    bprintf "webshell"
    rules=("eval(" "system(" "3c6e0b8a9c15224a")
    result=""
    length=${#rules[@]}
    # echo $length
    for ((i = 0; i<length;i++));do
        if ((i==length-1));then
            result="$result${rules[i]}"
        else 
            result="$result${rules[i]}\|"
        fi
    done
    grep -r $result /var/www/html 2>/dev/null
}

main(){
    Banner
    Basic_Info
    Invade_Identify
    Log_Analysis
    webshell
    BackDoor_Identify
    Evil_Process
}

main
exit

