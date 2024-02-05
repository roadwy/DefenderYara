
rule TrojanDownloader_Win32_Bancos_GL{
	meta:
		description = "TrojanDownloader:Win32/Bancos.GL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 62 69 74 2e 6c 79 2f } //01 00 
		$a_01_1 = {50 6f 77 65 72 53 68 65 6c 6c 20 28 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00 
		$a_01_3 = {6f 53 68 65 6c 6c 2e 72 75 6e 20 22 } //01 00 
		$a_01_4 = {29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 72 65 67 73 76 72 33 32 } //00 00 
		$a_00_5 = {5d 04 00 } //00 d6 
	condition:
		any of ($a_*)
 
}