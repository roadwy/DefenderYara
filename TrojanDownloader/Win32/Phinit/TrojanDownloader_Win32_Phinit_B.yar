
rule TrojanDownloader_Win32_Phinit_B{
	meta:
		description = "TrojanDownloader:Win32/Phinit.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 5c 6b 62 69 65 74 6d 70 32 2e 69 6e 69 } //01 00 
		$a_01_1 = {55 53 4e 53 56 43 } //01 00 
		$a_00_2 = {2f 75 70 2f 75 70 64 61 74 65 2e 68 74 6d } //01 00 
		$a_00_3 = {21 2a 26 2a 6e 6f 6e 65 2d 76 61 6c 75 65 2a 26 21 2a } //01 00 
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //00 00 
	condition:
		any of ($a_*)
 
}