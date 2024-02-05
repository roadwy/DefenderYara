
rule TrojanDownloader_Win32_DlRaser{
	meta:
		description = "TrojanDownloader:Win32/DlRaser,SIGNATURE_TYPE_PEHSTR,08 00 07 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 04 07 65 c6 04 03 78 c6 04 28 65 } //02 00 
		$a_01_1 = {3e 3e 20 4e 55 4c 20 2f 63 20 64 65 6c } //02 00 
		$a_01_2 = {2f 63 68 65 63 6b 2e 63 67 69 3f 69 64 3d } //01 00 
		$a_01_3 = {4d 69 63 72 6f 73 6f 66 74 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 } //01 00 
		$a_01_4 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e } //01 00 
		$a_01_5 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00 
		$a_01_6 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}