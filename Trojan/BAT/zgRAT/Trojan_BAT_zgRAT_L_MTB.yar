
rule Trojan_BAT_ZgRAT_L_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 08 11 04 91 20 ?? ?? 00 00 28 ?? ?? 00 06 11 04 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? ?? 00 0a 5d 28 ?? ?? 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_ZgRAT_L_MTB_2{
	meta:
		description = "Trojan:BAT/ZgRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {91 61 d2 9c 90 09 0e 00 02 11 ?? 02 11 ?? 91 03 11 ?? 03 8e 69 5d } //2
		$a_03_1 = {16 1f 20 9d 11 ?? 6f ?? 00 00 0a 13 ?? 20 90 09 0d 00 02 16 9a 17 8d ?? 00 00 01 13 ?? 11 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}