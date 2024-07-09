
rule Trojan_BAT_ClipBanker_BM_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 06 25 26 0a 06 28 ?? ?? 00 06 25 26 03 50 28 ?? ?? 00 06 25 26 28 ?? ?? 00 06 25 26 0b 28 } //2
		$a_03_1 = {0c 08 07 28 ?? ?? 00 06 08 28 ?? 00 00 06 25 26 28 ?? ?? 00 06 08 28 } //2
		$a_03_2 = {00 00 06 25 26 02 50 8e 69 28 ?? ?? 00 06 25 26 2a } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=6
 
}