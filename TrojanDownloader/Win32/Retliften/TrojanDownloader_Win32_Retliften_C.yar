
rule TrojanDownloader_Win32_Retliften_C{
	meta:
		description = "TrojanDownloader:Win32/Retliften.C,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {25 73 5c 6e 65 74 66 69 6c 74 65 72 2e 73 79 73 } //01 00 
		$a_01_1 = {63 2e 78 61 6c 6d } //01 00 
		$a_01_2 = {63 6f 6e 66 69 67 75 72 65 2e 78 61 6c 6d } //0a 00 
		$a_01_3 = {72 65 67 69 6e 69 00 } //0a 00 
		$a_01_4 = {61 74 73 76 32 2c 2e 3d 35 29 37 39 30 2f 3b 30 35 28 39 3b 31 33 36 37 } //00 00 
		$a_01_5 = {00 5d 04 00 00 93 91 04 80 5c 2a 00 00 94 91 04 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}