
rule TrojanDropper_Win32_Swisyn_G{
	meta:
		description = "TrojanDropper:Win32/Swisyn.G,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 07 00 00 05 00 "
		
	strings :
		$a_03_0 = {68 b8 0b 00 00 51 90 01 03 85 c0 74 5a 33 c0 8a 54 04 90 01 01 80 f2 90 01 01 80 ea 90 01 01 80 f2 90 01 01 88 54 04 90 01 01 40 3d b8 0b 00 00 7c e7 90 00 } //05 00 
		$a_03_1 = {4d 5a 00 00 77 62 00 90 02 10 2e 48 00 00 6f 63 78 00 90 00 } //01 00 
		$a_01_2 = {00 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c } //01 00 
		$a_01_3 = {00 78 69 61 6f 68 75 2e 6a 73 00 } //01 00 
		$a_01_4 = {5f 62 69 6e 64 2e 61 75 00 } //01 00 
		$a_01_5 = {5f 6d 75 74 69 2e 61 75 00 } //01 00 
		$a_01_6 = {00 63 73 62 6f 79 62 69 6e 64 2e 61 75 00 } //00 00  挀扳祯楢摮愮u
	condition:
		any of ($a_*)
 
}