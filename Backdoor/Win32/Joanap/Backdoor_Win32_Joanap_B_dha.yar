
rule Backdoor_Win32_Joanap_B_dha{
	meta:
		description = "Backdoor:Win32/Joanap.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 20 30 40 50 60 70 80 90 11 12 13 1a ff ee 48 } //01 00 
		$a_03_1 = {68 30 75 00 00 8d 44 24 0c 6a 04 50 56 c7 44 24 18 00 10 00 00 e8 90 01 02 00 00 83 c4 14 83 f8 ff 0f 90 01 02 00 00 00 8d 4c 24 08 51 e8 90 01 02 ff ff 6a 00 68 30 75 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_Joanap_B_dha_2{
	meta:
		description = "Backdoor:Win32/Joanap.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {10 20 30 40 50 60 70 80 90 11 12 13 1a ff ee 48 } //01 00 
		$a_03_1 = {68 30 75 00 00 8d 44 24 0c 6a 04 50 56 c7 44 24 18 00 10 00 00 e8 90 01 02 00 00 83 c4 14 83 f8 ff 0f 90 01 02 00 00 00 8d 4c 24 08 51 e8 90 01 02 ff ff 6a 00 68 30 75 00 00 90 00 } //00 00 
		$a_00_2 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}