
rule TrojanDownloader_BAT_Tiny_ATN_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a2 08 1f 2a 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2b 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2c 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2d 1f 90 01 01 8c 07 00 00 01 a2 08 1f 2e 1f 90 01 01 8c 07 00 00 01 a2 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Tiny_ATN_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ATN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 02 17 6f 90 01 01 00 00 0a 2d 2a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 02 28 90 01 01 00 00 06 02 28 90 01 01 00 00 06 02 28 90 00 } //01 00 
		$a_01_1 = {70 79 63 73 68 61 72 70 5c 70 79 63 73 68 61 72 70 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 70 79 63 73 68 61 72 70 2e 70 64 62 } //00 00  pycsharp\pycsharp\obj\Release\pycsharp.pdb
	condition:
		any of ($a_*)
 
}