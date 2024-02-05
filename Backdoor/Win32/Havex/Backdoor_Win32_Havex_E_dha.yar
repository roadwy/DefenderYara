
rule Backdoor_Win32_Havex_E_dha{
	meta:
		description = "Backdoor:Win32/Havex.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 58 3c 03 d8 83 c3 78 8b 1b 03 d8 33 d2 8b 4b 20 03 c8 56 52 } //01 00 
		$a_00_1 = {00 00 74 00 68 00 65 00 62 00 61 00 74 00 00 00 00 00 } //01 00 
		$a_00_2 = {00 00 73 00 6b 00 79 00 70 00 65 00 00 00 00 00 } //01 00 
		$a_00_3 = {00 00 64 00 64 00 65 00 78 00 2e 00 65 00 78 00 65 00 00 00 00 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 7e 
	condition:
		any of ($a_*)
 
}