
rule Trojan_Win64_Cobaltstrike_DI_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 84 24 88 00 00 00 99 b9 04 00 00 00 f7 f9 83 fa 01 41 0f 94 c0 41 80 e0 01 44 88 84 24 94 00 00 00 8b 0d 90 01 04 8b 15 90 01 04 41 89 c9 41 83 e9 01 41 0f af c9 83 e1 01 83 f9 00 41 0f 94 c0 83 fa 0a 41 0f 9c c2 45 08 d0 41 f6 c0 01 b9 26 c4 9f ff ba da ac a6 46 0f 45 d1 89 94 24 80 00 00 00 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}