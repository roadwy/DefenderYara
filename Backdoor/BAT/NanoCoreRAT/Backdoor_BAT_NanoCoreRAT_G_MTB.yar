
rule Backdoor_BAT_NanoCoreRAT_G_MTB{
	meta:
		description = "Backdoor:BAT/NanoCoreRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 01 38 } //2
		$a_03_1 = {00 00 01 25 16 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 25 17 20 ?? ?? ?? 00 28 ?? ?? 00 06 a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 01 38 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}