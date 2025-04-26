
rule Trojan_Win64_CobaltStrike_GG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 ca 46 0f b6 8c 0c ?? ?? ?? ?? 44 32 0c 0a 44 88 0c 17 4c 89 c2 49 81 f8 09 0e 04 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}