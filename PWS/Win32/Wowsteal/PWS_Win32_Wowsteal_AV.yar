
rule PWS_Win32_Wowsteal_AV{
	meta:
		description = "PWS:Win32/Wowsteal.AV,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {25 64 25 64 79 6d 67 2e 64 6c 6c } //01 00  %d%dymg.dll
		$a_01_1 = {47 78 57 69 6e 64 6f 77 43 6c 61 73 73 44 33 64 } //01 00  GxWindowClassD3d
		$a_01_2 = {41 70 70 49 6e 69 74 5f 44 4c 4c 73 } //02 00  AppInit_DLLs
		$a_00_3 = {64 61 65 72 68 74 65 74 6f 6d 65 72 65 74 61 65 72 63 } //00 00  daerhtetomeretaerc
	condition:
		any of ($a_*)
 
}