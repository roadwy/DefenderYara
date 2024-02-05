
rule PWS_Win32_Frethog_AU{
	meta:
		description = "PWS:Win32/Frethog.AU,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 04 00 "
		
	strings :
		$a_03_0 = {6a fb 58 2b 46 04 6a 05 01 06 8d 46 ff 50 ff 76 04 53 e8 90 01 04 8b 46 04 83 c4 10 83 c0 05 01 06 83 c6 09 4f 90 00 } //01 00 
		$a_01_1 = {46 6f 72 74 68 67 6f 65 72 00 } //01 00 
		$a_01_2 = {62 3d 25 73 26 63 3d 25 73 26 65 3d 25 73 26 66 3d 25 73 26 68 3d 25 73 26 6b 3d 25 73 26 6c 3d 25 73 26 6d 3d 25 73 26 6e 3d 25 75 26 73 3d 25 64 26 71 3d 25 73 } //01 00 
		$a_01_3 = {78 79 6d 61 69 6e 2e 62 69 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}