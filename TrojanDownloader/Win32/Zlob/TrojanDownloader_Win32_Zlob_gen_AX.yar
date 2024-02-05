
rule TrojanDownloader_Win32_Zlob_gen_AX{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {70 00 3d 00 25 00 64 00 90 09 06 00 90 03 06 0f 73 00 74 00 65 00 90 01 0e 00 00 00 00 3f 00 73 00 74 00 65 00 90 00 } //02 00 
		$a_01_1 = {49 73 6f 6c 61 74 69 6f 6e 41 77 61 72 65 43 6c 65 61 6e 75 70 0a 00 } //01 00 
		$a_03_2 = {83 e8 46 8b 90 01 01 14 74 90 01 01 83 e8 33 74 90 01 01 2d 90 00 } //01 00 
		$a_03_3 = {2e 01 00 00 90 09 03 00 6a 90 03 01 01 16 1c 90 03 01 01 68 b8 90 00 } //01 00 
		$a_01_4 = {88 a6 a5 a9 a1 ea ab ae } //01 00 
		$a_01_5 = {c8 e6 e5 e9 e1 aa eb ee } //02 00 
		$a_01_6 = {66 67 64 79 2e 64 6c 6c 00 } //02 00 
		$a_01_7 = {68 6c 65 6f 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}