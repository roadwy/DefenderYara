
rule Worm_Win32_Yimper{
	meta:
		description = "Worm:Win32/Yimper,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 6d 73 67 72 3a 53 65 6e 64 49 4d 3f } //01 00  ymsgr:SendIM?
		$a_01_1 = {5c 61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  \autorun.inf
		$a_01_2 = {55 53 45 52 3d 25 73 20 50 41 53 53 3d 25 73 } //01 00  USER=%s PASS=%s
		$a_03_3 = {41 75 74 6f 52 75 6e 90 02 02 5d 90 02 02 0d 0a 4f 50 45 4e 3d 90 00 } //02 00 
		$a_03_4 = {6a 01 68 58 04 00 00 68 00 01 00 00 6a 02 90 01 01 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}