
rule Trojan_BAT_Pretoria_ZLR_MTB{
	meta:
		description = "Trojan:BAT/Pretoria.ZLR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {1f 09 0b 04 03 07 5d 9a 28 ?? 00 00 0a 02 28 ?? 00 00 06 28 ?? 01 00 0a 0a 2b 00 06 2a } //6
		$a_03_1 = {02 07 02 07 91 07 03 28 ?? 01 00 06 9c 07 17 d6 0b 07 06 31 eb 2a } //5
		$a_03_2 = {02 03 04 28 ?? 01 00 06 00 02 0a 2b 00 06 2a } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5+(#a_03_2  & 1)*4) >=15
 
}