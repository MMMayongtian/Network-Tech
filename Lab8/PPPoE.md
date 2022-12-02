### PPPoE

enable

config terminal

interface virtual-template 1

ip unnumbered fa0/0

peer default ip address pool myPool

ppp authentication chap myPPPoE

exit

bba-group pppoe myBBAGroup

virtual-template 1

exit

interface fa0/0

pppoe enable group myBBAGroup

exit

### 标准ACL

access-list 6 permit 202.113.26.0 0.0.0.255
access-list 6 deny any
interface fa0/1
ip access-group 6 in
exit

![image-20221130235050606](https://raw.githubusercontent.com/MMMayongtian/Notes-Img/main/typora/image-20221130235050606.png?token=AXPWZZLCABZKFYLGTJMRFADDQ56B4)

### 扩展ACL

Router#config terminal
End with CNTI/Z.Enter confiquration commands, one per line.202.113.26.2 host 202.113.25.3 eg 80
access-list 106 deny tcp
Router(config)#access-list 106 deny tcp host 202.113.26.2 host 202.113.25.3 eq 80
Router(config)#access-list 106 permit ip any any
Router(config)#interface fa0/1
Router(config-if)#ip access-group 106 in
Router(config-if)#exit

![image-20221130235108148](https://raw.githubusercontent.com/MMMayongtian/Notes-Img/main/typora/image-20221130235108148.png?token=AXPWZZLFI2MN3D45GSCBNVDDQ56CS)

