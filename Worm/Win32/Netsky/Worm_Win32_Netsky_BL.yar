
rule Worm_Win32_Netsky_BL{
	meta:
		description = "Worm:Win32/Netsky.BL,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e0 30 c1 e2 02 c1 f8 04 00 d0 88 45 d8 88 ca c0 e2 04 } //01 00 
		$a_00_1 = {43 3a 5c 49 6e 74 65 6c 5c 49 41 41 6e 6f 74 69 66 2e 65 78 65 20 2d 73 } //01 00  C:\Intel\IAAnotif.exe -s
		$a_01_2 = {c7 03 68 65 6c 6f c7 43 04 20 6d 65 2e c7 43 08 73 6f 6d 65 c7 43 0c 70 61 6c 61 c7 43 10 63 65 2e 63 } //01 00 
		$a_00_3 = {c7 03 4d 41 49 4c c7 43 04 20 46 52 4f c7 43 08 4d 3a 3c 00 } //00 00 
	condition:
		any of ($a_*)
 
}