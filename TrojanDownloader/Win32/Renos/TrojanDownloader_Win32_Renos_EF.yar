
rule TrojanDownloader_Win32_Renos_EF{
	meta:
		description = "TrojanDownloader:Win32/Renos.EF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 f1 a3 88 0c } //02 00 
		$a_01_1 = {3f 3e 8c 8d 01 00 } //02 00 
		$a_01_2 = {43 01 51 1b 63 97 e3 95 67 00 } //01 00 
		$a_01_3 = {8d 45 e4 6a 0c 50 68 00 14 2d 00 } //01 00 
		$a_01_4 = {85 c0 74 6f 83 7d ec 04 75 69 a0 } //00 00 
	condition:
		any of ($a_*)
 
}