
rule TrojanDownloader_Win32_Monkif_H{
	meta:
		description = "TrojanDownloader:Win32/Monkif.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 74 04 83 c0 } //01 00 
		$a_03_1 = {55 46 ff d7 3b f0 7c e9 5b 5f c6 86 90 09 08 00 2c 90 01 01 88 86 90 00 } //01 00 
		$a_01_2 = {67 2b 00 00 74 36 6a 02 } //00 00 
	condition:
		any of ($a_*)
 
}