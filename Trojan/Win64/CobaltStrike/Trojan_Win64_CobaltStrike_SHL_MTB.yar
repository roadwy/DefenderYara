
rule Trojan_Win64_CobaltStrike_SHL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SHL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 88 0c 1c 48 ff c3 41 f7 e9 41 03 d1 c1 fa 07 8b c2 c1 e8 1f 03 d0 41 8b c1 41 ff c1 69 d2 d9 00 00 00 2b c2 48 98 0f b6 0c 38 88 8c 1c ff 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}