
rule TrojanDownloader_Win32_Zlob_ACA{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ACA,SIGNATURE_TYPE_PEHSTR,29 00 29 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 00 54 00 4c 00 3a 00 25 00 70 00 } //0a 00 
		$a_01_1 = {49 6e 74 65 72 6c 6f 63 6b 65 64 50 6f 70 45 6e 74 72 79 53 4c 69 73 74 } //0a 00 
		$a_01_2 = {43 6f 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //0a 00 
		$a_01_3 = {53 74 72 69 6e 67 46 72 6f 6d 47 55 49 44 32 } //01 00 
		$a_01_4 = {71 6e 64 73 66 6d 61 6f 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00 
		$a_01_5 = {73 71 76 67 6e 72 70 78 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}