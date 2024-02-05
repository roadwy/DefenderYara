
rule TrojanDownloader_Win32_Enameler_B_dha{
	meta:
		description = "TrojanDownloader:Win32/Enameler.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 73 2e 65 78 65 } //01 00 
		$a_01_1 = {2f 66 69 6c 65 73 2f 69 6e 64 65 78 2e 70 68 70 3f } //01 00 
		$a_01_2 = {45 4e 41 4d 45 4c 49 42 } //01 00 
		$a_01_3 = {67 6e 61 6d 65 } //01 00 
		$a_01_4 = {6d 73 64 74 63 70 77 65 2e 64 61 74 } //01 00 
		$a_01_5 = {68 74 6d 6c 3c 27 27 4b 28 2a } //00 00 
	condition:
		any of ($a_*)
 
}