
rule Trojan_Win32_Zusy_GMC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c4 14 48 89 35 90 01 01 a9 a5 00 5f 5e a3 8c a9 a5 00 5b 90 00 } //0a 00 
		$a_03_1 = {68 04 01 00 00 56 53 ff 15 90 01 04 a1 38 b0 a5 00 89 35 a8 a9 a5 00 8b fe 38 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_GMC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {68 04 01 00 00 56 53 ff 15 90 01 04 a1 90 01 01 b0 a5 00 89 35 90 01 01 a9 a5 00 8b fe 38 18 90 00 } //0a 00 
		$a_03_1 = {8b 45 fc 83 c4 14 48 89 35 90 01 01 a9 a5 00 5f 5e a3 90 01 01 a9 a5 00 5b c9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zusy_GMC_MTB_3{
	meta:
		description = "Trojan:Win32/Zusy.GMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {50 8b 45 fc 8d 04 86 50 56 57 e8 90 01 04 8b 45 fc 83 c4 14 48 89 35 a8 bc 45 01 5f 5e a3 a4 bc 45 01 5b c9 c3 90 00 } //01 00 
		$a_80_1 = {53 74 65 61 6d 53 65 72 76 69 63 65 2e 65 78 65 } //SteamService.exe  01 00 
		$a_01_2 = {40 2e 69 38 31 35 } //00 00 
	condition:
		any of ($a_*)
 
}