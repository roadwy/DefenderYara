
rule TrojanClicker_Win32_Clidak_A{
	meta:
		description = "TrojanClicker:Win32/Clidak.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {8b 4d f8 c6 41 03 23 8b 55 f8 c6 42 02 23 8b 45 f8 c6 40 01 23 } //0a 00 
		$a_02_1 = {77 69 6e 64 6f 77 2e 73 68 6f 77 4d 6f 64 90 01 22 77 69 6e 64 6f 77 2e 6f 70 65 6e 3d 6e 75 6c 6c 3b 90 02 30 00 73 63 72 69 70 74 00 00 74 90 00 } //0a 00 
		$a_00_2 = {6a 01 6a 07 6a 01 6a 06 6a 01 6a 05 6a 01 6a 04 } //00 00 
	condition:
		any of ($a_*)
 
}