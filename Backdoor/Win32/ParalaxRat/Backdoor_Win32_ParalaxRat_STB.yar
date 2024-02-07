
rule Backdoor_Win32_ParalaxRat_STB{
	meta:
		description = "Backdoor:Win32/ParalaxRat.STB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b c1 83 e0 1f 8a 44 05 dc 30 81 90 01 04 41 81 f9 00 60 00 00 72 e8 b8 90 01 04 ff d0 90 00 } //01 00 
		$a_03_1 = {b0 36 00 00 7c 90 01 01 42 81 fa 80 fc 0a 00 7c 90 01 01 c7 45 dc 90 00 } //01 00 
		$a_03_2 = {6a 40 68 00 60 00 00 68 90 01 04 ff 55 f4 c7 45 f0 90 01 04 ff 65 f0 90 00 } //02 00 
		$a_03_3 = {3d 40 1f 00 00 7c ee 42 81 fa b0 8f 06 00 7c e3 c7 45 d0 90 02 0a c7 45 d4 90 01 04 c7 45 d8 90 01 04 c7 45 dc 90 00 } //00 00 
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}