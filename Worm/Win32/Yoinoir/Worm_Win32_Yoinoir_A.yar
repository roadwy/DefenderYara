
rule Worm_Win32_Yoinoir_A{
	meta:
		description = "Worm:Win32/Yoinoir.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 f8 02 75 19 8d 45 f8 8b d3 e8 90 01 04 8b 55 f8 8b c6 b9 90 01 04 e8 90 01 04 43 83 fb 5b 75 b7 90 00 } //01 00 
		$a_03_1 = {66 c7 45 ea 50 00 8d 45 da 50 e8 90 01 04 85 c0 0f 94 c3 90 00 } //01 00 
		$a_01_2 = {67 70 75 70 64 61 74 65 00 } //01 00 
		$a_01_3 = {55 73 65 41 75 74 6f 50 6c 61 79 3d 31 00 } //00 00 
	condition:
		any of ($a_*)
 
}