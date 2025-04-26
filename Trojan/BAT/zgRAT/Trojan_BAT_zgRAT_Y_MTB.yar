
rule Trojan_BAT_ZgRAT_Y_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 00 04 00 00 8d ?? 00 00 01 13 01 20 } //2
		$a_03_1 = {0a 14 14 6f ?? 00 00 0a 26 20 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}