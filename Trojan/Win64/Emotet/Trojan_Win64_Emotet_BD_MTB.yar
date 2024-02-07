
rule Trojan_Win64_Emotet_BD_MTB{
	meta:
		description = "Trojan:Win64/Emotet.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {8a 04 1f 42 32 04 27 41 88 44 3d 00 48 ff c7 48 81 ff 90 01 04 0f 85 5d ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_Emotet_BD_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b c2 48 98 48 8b 0d 90 01 04 0f b6 04 01 8b 8c 24 90 01 04 33 c8 8b c1 48 63 4c 24 90 01 01 48 8b 94 24 90 01 04 88 04 0a e9 90 00 } //01 00 
		$a_03_1 = {8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 48 8b 05 90 01 04 48 63 d1 0f b6 0c 02 32 4c 2b ff 88 4b ff 48 83 ee 01 75 90 00 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllRegisterServer
	condition:
		any of ($a_*)
 
}