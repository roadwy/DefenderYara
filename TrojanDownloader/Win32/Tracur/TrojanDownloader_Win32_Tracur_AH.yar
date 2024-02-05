
rule TrojanDownloader_Win32_Tracur_AH{
	meta:
		description = "TrojanDownloader:Win32/Tracur.AH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 72 66 69 76 76 65 75 65 6c 75 62 2e 64 6c 6c } //01 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 32 31 33 2e 31 37 34 2e 31 34 31 2e 31 31 2f 78 6d 6c 3f 61 3d } //01 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 90 02 20 67 6f 6f 67 6c 65 20 66 61 63 65 62 6f 6f 6b 20 62 69 6e 67 20 79 61 68 6f 6f 20 61 6f 6c 20 79 6f 75 74 75 62 65 20 6d 73 6e 20 68 6f 74 6d 61 69 6c 20 67 6d 61 69 6c 90 02 20 2e 63 6f 6d 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}