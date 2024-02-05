
rule TrojanDownloader_Win32_Bizdup{
	meta:
		description = "TrojanDownloader:Win32/Bizdup,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 00 00 00 50 6c 75 67 4c 69 73 74 00 } //01 00 
		$a_01_1 = {07 00 00 00 43 75 63 6b 6f 6f } //01 00 
		$a_01_2 = {08 00 00 00 7e 75 70 73 2e 6c 6f 67 00 } //01 00 
		$a_03_3 = {2f 6e 65 77 75 70 90 01 01 2e 74 78 74 00 90 00 } //01 00 
		$a_01_4 = {54 68 69 72 64 53 6f 66 74 49 6e 66 6f 32 } //01 00 
		$a_01_5 = {3f 53 6f 66 74 4e 61 6d 65 3d } //01 00 
		$a_01_6 = {53 65 6e 64 53 6f 66 74 49 6e 66 6f 32 } //01 00 
		$a_01_7 = {d7 a2 b2 e1 b1 ed be af b8 e6 00 } //00 00 
	condition:
		any of ($a_*)
 
}