
rule Trojan_Linux_FirewallOutHttpsBlock_PI3{
	meta:
		description = "Trojan:Linux/FirewallOutHttpsBlock.PI3,SIGNATURE_TYPE_CMDHSTR_EXT,52 00 52 00 09 00 00 "
		
	strings :
		$a_81_0 = {2d 41 20 4f 55 54 50 55 54 20 } //20 -A OUTPUT 
		$a_81_1 = {20 2d 70 20 74 63 70 20 } //20  -p tcp 
		$a_81_2 = {70 6f 72 74 20 34 34 33 20 } //20 port 443 
		$a_81_3 = {2d 6a 20 44 52 4f 50 } //20 -j DROP
		$a_81_4 = {3e 20 2f 65 74 63 2f 69 70 74 61 62 6c 65 73 2f 72 75 6c 65 73 2e 76 34 } //2 > /etc/iptables/rules.v4
		$a_81_5 = {3e 20 2f 65 74 63 2f 69 70 74 61 62 6c 65 73 2f 72 75 6c 65 73 2e 76 36 } //2 > /etc/iptables/rules.v6
		$a_81_6 = {3e 20 2f 65 74 63 2f 73 79 73 63 6f 6e 66 69 67 2f 69 70 74 61 62 6c 65 73 } //2 > /etc/sysconfig/iptables
		$a_81_7 = {3e 20 2f 65 74 63 2f 73 79 73 63 6f 6e 66 69 67 2f 69 70 36 74 61 62 6c 65 73 } //2 > /etc/sysconfig/ip6tables
		$a_81_8 = {73 70 6f 72 74 20 34 34 33 20 } //-20 sport 443 
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2+(#a_81_6  & 1)*2+(#a_81_7  & 1)*2+(#a_81_8  & 1)*-20) >=82
 
}