
rule Trojan_Linux_FirewallOutHttpsBlock_PI2{
	meta:
		description = "Trojan:Linux/FirewallOutHttpsBlock.PI2,SIGNATURE_TYPE_CMDHSTR_EXT,2d 00 2d 00 07 00 00 "
		
	strings :
		$a_81_0 = {69 70 74 61 62 6c 65 73 20 } //5 iptables 
		$a_81_1 = {69 70 36 74 61 62 6c 65 73 20 } //5 ip6tables 
		$a_81_2 = {20 4f 55 54 50 55 54 20 } //10  OUTPUT 
		$a_81_3 = {20 2d 70 20 74 63 70 20 } //10  -p tcp 
		$a_81_4 = {70 6f 72 74 20 34 34 33 20 } //10 port 443 
		$a_81_5 = {2d 6a 20 44 52 4f 50 } //10 -j DROP
		$a_81_6 = {73 70 6f 72 74 20 34 34 33 20 } //-10 sport 443 
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*10+(#a_81_5  & 1)*10+(#a_81_6  & 1)*-10) >=45
 
}