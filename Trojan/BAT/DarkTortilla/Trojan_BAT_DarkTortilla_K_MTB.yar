
rule Trojan_BAT_DarkTortilla_K_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 6a 23 } //2
		$a_03_1 = {00 00 0a b9 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 18 13 07 38 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}