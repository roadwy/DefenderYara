
rule Trojan_Win64_CobaltStrike_DB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 11 0f b6 c2 41 32 c0 88 01 44 0f b6 c2 48 ff c1 49 3b c9 72 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_DB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 88 04 01 b8 ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 33 8b ?? ?? ?? ?? ff 43 ?? 2b c1 01 05 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 43 ?? 49 ?? ?? ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}