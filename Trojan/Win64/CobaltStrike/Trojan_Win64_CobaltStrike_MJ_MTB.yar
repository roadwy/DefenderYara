
rule Trojan_Win64_CobaltStrike_MJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f a2 44 8b c9 c7 05 00 91 05 00 01 00 00 00 81 f1 63 41 4d 44 44 8b d2 81 f2 65 6e 74 69 8b fb 81 f7 41 75 74 68 8b f0 0b fa 44 8b c3 0b f9 41 81 f0 47 65 6e 75 33 c9 41 81 f2 69 6e 65 49 45 0b d0 b8 01 00 00 00 44 8b 05 49 b4 05 00 41 81 f1 6e 74 65 6c 45 0b d1 } //00 00 
	condition:
		any of ($a_*)
 
}