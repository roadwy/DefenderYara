
rule Trojan_BAT_zgRAT_F_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 1f 10 11 04 16 03 8e 69 1f 10 da 28 } //2
		$a_03_1 = {11 09 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 13 07 90 00 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}