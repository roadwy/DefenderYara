
rule Trojan_Linux_Rbot_BR2{
	meta:
		description = "Trojan:Linux/Rbot.BR2,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {2f 00 62 00 6f 00 74 00 70 00 69 00 6c 00 6c 00 65 00 64 00 2f 00 72 00 62 00 6f 00 74 00 } //1 /botpilled/rbot
	condition:
		((#a_00_0  & 1)*1) >=1
 
}