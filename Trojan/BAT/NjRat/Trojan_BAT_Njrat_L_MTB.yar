
rule Trojan_BAT_NjRAT_L_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 7e ?? 00 00 04 11 04 02 16 02 8e 69 28 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_NjRAT_L_MTB_2{
	meta:
		description = "Trojan:BAT/NjRAT.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 ?? ?? ?? ?? ?? 5f 91 06 11 04 91 61 9c 2b 07 13 07 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}