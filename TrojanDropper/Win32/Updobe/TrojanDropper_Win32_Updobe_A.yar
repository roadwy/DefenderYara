
rule TrojanDropper_Win32_Updobe_A{
	meta:
		description = "TrojanDropper:Win32/Updobe.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 41 64 6f 62 65 5c 46 6c 61 73 68 } //02 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 6f 7a 69 6c 6c 61 5c 46 69 72 65 66 6f 78 5c 45 78 74 65 6e 73 69 6f 6e 73 } //02 00 
		$a_01_2 = {31 39 31 64 33 66 31 34 2d 66 66 34 63 2d 34 38 39 35 2d 62 64 65 61 2d 64 62 35 34 35 32 36 63 62 34 39 61 } //01 00 
		$a_01_3 = {00 69 6e 73 74 61 6c 6c 2e } //01 00 
		$a_01_4 = {00 6f 76 65 72 6c 61 79 2e } //01 00 
		$a_01_5 = {00 67 6f 6f 67 6c 65 2e } //00 00 
	condition:
		any of ($a_*)
 
}