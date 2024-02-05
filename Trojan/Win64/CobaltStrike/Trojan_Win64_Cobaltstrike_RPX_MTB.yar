
rule Trojan_Win64_Cobaltstrike_RPX_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 89 c2 83 e2 03 8a 54 15 00 32 14 07 88 14 03 48 ff c0 eb e7 } //01 00 
		$a_01_1 = {49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Cobaltstrike_RPX_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4d e8 b8 e3 01 00 00 8b 55 f4 44 8b 4d f0 2b d0 44 8b 55 e0 41 81 f1 f0 00 00 00 44 8b 45 e4 41 81 ea ab 07 00 00 44 2b c0 8b 45 ec 05 8b 05 00 00 89 44 24 30 44 89 44 24 28 4d 8b c6 44 89 54 24 20 } //00 00 
	condition:
		any of ($a_*)
 
}