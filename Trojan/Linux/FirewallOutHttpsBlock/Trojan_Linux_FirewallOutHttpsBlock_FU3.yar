
rule Trojan_Linux_FirewallOutHttpsBlock_FU3{
	meta:
		description = "Trojan:Linux/FirewallOutHttpsBlock.FU3,SIGNATURE_TYPE_CMDHSTR_EXT,52 00 52 00 06 00 00 "
		
	strings :
		$a_81_0 = {75 66 77 2d 75 73 65 72 2d 6f 75 74 70 75 74 20 } //20 ufw-user-output 
		$a_81_1 = {20 2d 70 20 74 63 70 20 } //20  -p tcp 
		$a_81_2 = {70 6f 72 74 20 34 34 33 20 } //20 port 443 
		$a_81_3 = {2d 6a 20 52 45 4a 45 43 54 } //20 -j REJECT
		$a_81_4 = {3e 20 2f 65 74 63 2f 75 66 77 2f 75 73 65 72 2e 72 75 6c 65 73 } //2 > /etc/ufw/user.rules
		$a_81_5 = {73 70 6f 72 74 20 34 34 33 20 } //-20 sport 443 
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*20+(#a_81_4  & 1)*2+(#a_81_5  & 1)*-20) >=82
 
}