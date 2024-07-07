
rule Trojan_BAT_DarkTortilla_M_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 28 90 01 02 00 06 a2 14 14 14 28 90 00 } //2
		$a_03_1 = {00 00 01 25 17 28 90 01 01 00 00 2b a2 14 14 14 17 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}