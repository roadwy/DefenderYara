
rule Trojan_BAT_zgRAT_I_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 } //2
		$a_03_1 = {09 11 05 16 11 05 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 07 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}