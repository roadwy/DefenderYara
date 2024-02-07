
rule Worm_Win32_Bundiso_A{
	meta:
		description = "Worm:Win32/Bundiso.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {34 6d 75 10 c7 45 fc 90 01 01 00 00 00 8b 90 01 01 08 66 c7 90 01 01 34 63 00 c7 45 f0 00 00 00 00 68 90 01 04 eb 90 00 } //01 00 
		$a_00_1 = {3a 00 5c 00 6d 00 6f 00 76 00 69 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  :\movies.exe
		$a_00_2 = {3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //01 00  :\autorun.inf
		$a_00_3 = {5c 00 53 00 61 00 6e 00 63 00 68 00 69 00 74 00 68 00 61 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 76 00 69 00 72 00 75 00 73 00 } //00 00  \Sanchitha\Desktop\virus
	condition:
		any of ($a_*)
 
}