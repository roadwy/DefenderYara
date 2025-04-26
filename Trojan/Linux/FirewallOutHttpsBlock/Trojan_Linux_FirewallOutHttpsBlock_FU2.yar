
rule Trojan_Linux_FirewallOutHttpsBlock_FU2{
	meta:
		description = "Trojan:Linux/FirewallOutHttpsBlock.FU2,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_81_0 = {75 66 77 20 64 65 6e 79 20 6f 75 74 20 74 6f 20 61 6e 79 20 70 6f 72 74 20 34 34 33 } //10 ufw deny out to any port 443
		$a_81_1 = {75 66 77 20 64 65 6e 79 20 6f 75 74 20 68 74 74 70 73 } //10 ufw deny out https
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10) >=10
 
}