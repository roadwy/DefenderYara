
rule Backdoor_Win32_Liudoor_B_dha{
	meta:
		description = "Backdoor:Win32/Liudoor.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 64 6c 6c 73 65 72 76 65 72 2e 64 6c 6c 00 } //01 00 
		$a_01_1 = {53 75 63 63 00 00 00 00 46 61 69 6c 00 } //01 00 
		$a_03_2 = {55 8b ee 81 ed 90 01 04 8a 84 2a 90 01 04 8b fe 34 1f 83 c9 ff 88 82 90 01 04 33 c0 42 f2 ae f7 d1 49 3b d1 72 e0 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}