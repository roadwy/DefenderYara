
rule Backdoor_Win32_Zegost_DP{
	meta:
		description = "Backdoor:Win32/Zegost.DP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 3e c6 45 90 01 01 46 c6 45 90 01 01 55 c6 45 90 01 01 43 c6 45 90 01 01 4b c6 45 90 01 01 33 90 00 } //01 00 
		$a_01_1 = {8a 06 32 c2 02 c2 88 06 46 49 75 } //01 00 
		$a_01_2 = {25 73 20 2f 76 20 22 25 73 5c 63 6f 6e 66 69 67 5c 73 61 6d 22 20 22 25 73 64 66 65 72 2e 64 61 74 } //00 00  %s /v "%s\config\sam" "%sdfer.dat
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}