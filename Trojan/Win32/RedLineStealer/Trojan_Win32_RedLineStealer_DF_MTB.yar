
rule Trojan_Win32_RedLineStealer_DF_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 8b 55 d8 31 02 6a 66 e8 90 01 04 bb 04 00 00 00 2b d8 6a 66 e8 90 01 04 03 d8 01 5d ec 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_RedLineStealer_DF_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {77 65 64 73 79 63 64 73 73 64 66 61 65 73 66 } //03 00 
		$a_81_1 = {56 75 6d 65 6e 64 73 6b 69 6d 65 73 } //03 00 
		$a_81_2 = {77 61 6e 75 6d 65 73 66 72 73 63 73 61 73 66 76 32 } //03 00 
		$a_81_3 = {6d 6f 64 52 65 70 6c 61 63 65 } //03 00 
		$a_81_4 = {43 6f 64 65 6a 6f 63 6b 2e 46 6c 6f 77 47 72 61 70 68 } //03 00 
		$a_81_5 = {74 78 74 50 61 73 73 77 6f 72 64 } //03 00 
		$a_81_6 = {63 68 6b 4c 6f 61 64 54 69 70 73 41 74 53 74 61 72 74 75 70 } //00 00 
	condition:
		any of ($a_*)
 
}