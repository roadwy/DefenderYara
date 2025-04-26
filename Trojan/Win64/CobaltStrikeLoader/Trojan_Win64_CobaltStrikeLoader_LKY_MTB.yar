
rule Trojan_Win64_CobaltStrikeLoader_LKY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrikeLoader.LKY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 1f 03 d0 [0-20] 42 8a 8c ?? ?? ?? ?? ?? 43 32 8c ?? ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 41 88 0c ?? 44 03 cf 4c 03 ?? 44 3b 8d ?? ?? 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}