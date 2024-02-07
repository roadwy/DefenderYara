
rule Trojan_Win32_Emotet_PBD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //02 00  DllRegisterServer
		$a_03_1 = {2b d7 03 54 24 90 01 01 03 54 24 90 01 01 03 54 24 90 01 01 0f b6 14 02 8b 44 24 90 01 01 30 54 28 90 01 01 3b ac 24 90 02 04 0f 82 90 00 } //02 00 
		$a_03_2 = {03 d7 03 54 24 90 01 01 03 54 24 90 01 01 0f b6 14 02 8b 44 24 90 01 01 30 54 28 90 01 01 3b 6c 24 90 01 01 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Emotet_PBD_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 90 01 01 0f b6 04 2b 03 c2 33 d2 f7 35 90 01 04 8a 04 2a 8b 54 24 90 01 01 32 04 11 8b 54 24 90 01 01 88 04 11 90 00 } //01 00 
		$a_81_1 = {71 71 36 32 77 66 54 5a 56 63 39 73 63 76 65 24 72 69 64 69 25 4e 46 7a 4a 69 44 6b 6a 71 69 7c 37 6d 4e 78 7b 79 6e 6c 59 42 5a 65 4f 4a 4e 64 7e 66 58 6d 34 73 7c 63 79 53 6f 6e 56 4e 40 53 4f 30 77 31 7e 7b 46 43 37 58 31 51 6b 72 3f 62 36 5a 61 70 68 74 } //00 00  qq62wfTZVc9scve$ridi%NFzJiDkjqi|7mNx{ynlYBZeOJNd~fXm4s|cySonVN@SO0w1~{FC7X1Qkr?b6Zapht
	condition:
		any of ($a_*)
 
}