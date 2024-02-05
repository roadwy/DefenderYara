
rule Trojan_Win32_Ursnif_RF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c1 14 52 09 01 89 90 01 05 8b 90 01 05 03 90 01 02 a1 90 01 04 89 90 01 05 69 90 01 05 ba 64 01 00 0f b7 55 90 01 01 2b ca 66 90 01 03 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 57 a1 90 01 04 a3 90 01 04 8b 90 01 05 89 90 01 05 8b 90 01 05 8b 90 01 01 a3 90 01 04 8b 90 01 05 83 90 01 02 89 90 01 05 8b 90 01 05 83 90 01 02 a1 90 01 04 a3 90 01 04 a1 90 01 04 8b d2 90 01 3e 31 90 01 05 8b 90 01 01 c7 90 01 09 a1 90 01 04 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 55 10 89 55 e4 8b 90 01 02 83 90 01 02 89 90 01 02 83 90 01 03 0f 90 01 05 8b 90 01 02 83 90 01 02 0f 90 01 03 2b 90 01 01 a1 90 01 04 2b 90 01 01 a3 90 01 04 8b 90 01 02 8b 90 01 02 8a 90 01 01 88 90 01 01 8b 90 01 02 83 90 00 } //01 00 
		$a_02_1 = {83 c1 3b 2b 90 01 05 89 90 01 02 eb 90 01 01 8b 90 01 05 83 90 01 02 2b 90 01 02 89 90 01 05 eb 90 01 01 8b 90 01 02 83 90 01 02 2b 90 01 05 8b 90 01 05 2b 90 01 01 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ursnif_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Ursnif.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_81_0 = {63 3a 5c 54 68 65 79 5c 62 79 5c 53 61 79 5c 44 72 69 76 65 5c 36 35 30 2d 42 72 65 61 6b 5c 50 72 6f 64 75 63 74 2e 70 64 62 } //01 00 
		$a_81_1 = {47 65 74 43 50 49 6e 66 6f } //01 00 
		$a_81_2 = {47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 57 } //01 00 
		$a_81_3 = {47 65 74 4c 6f 63 61 6c 65 49 6e 66 6f 57 } //01 00 
		$a_81_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00 
		$a_81_5 = {53 65 74 53 65 63 75 72 69 74 79 44 65 73 63 72 69 70 74 6f 72 44 61 63 6c } //00 00 
	condition:
		any of ($a_*)
 
}