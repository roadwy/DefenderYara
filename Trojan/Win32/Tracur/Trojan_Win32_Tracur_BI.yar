
rule Trojan_Win32_Tracur_BI{
	meta:
		description = "Trojan:Win32/Tracur.BI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {71 6b 77 3d 00 } //01 00 
		$a_01_1 = {6d 3d 25 73 26 7a 3d 25 73 } //01 00 
		$a_03_2 = {8a 4c 16 01 32 8b 90 01 04 88 0c 10 42 43 3b d7 72 e6 90 00 } //01 00 
		$a_01_3 = {8b 5d f8 80 3c 1f 6b 75 36 80 7c 1f 01 31 75 2f 80 7c 1f 02 20 75 28 80 7c 1f 03 3d 75 21 80 7c 1f 04 22 } //00 00 
		$a_00_4 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}