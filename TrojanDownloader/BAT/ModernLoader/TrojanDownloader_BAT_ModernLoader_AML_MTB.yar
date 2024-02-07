
rule TrojanDownloader_BAT_ModernLoader_AML_MTB{
	meta:
		description = "TrojanDownloader:BAT/ModernLoader.AML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 0f 00 00 06 d0 29 00 00 01 28 90 01 03 0a 72 f5 00 00 70 28 90 01 03 0a 16 8c 2b 00 00 01 14 6f 90 01 03 0a 74 1a 00 00 01 0a 25 06 72 09 01 00 70 28 90 00 } //01 00 
		$a_01_1 = {53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 } //01 00  Sandbox execution is not allowed
		$a_01_2 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 20 00 6d 00 61 00 63 00 68 00 69 00 6e 00 65 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 20 00 69 00 73 00 20 00 6e 00 6f 00 74 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 } //00 00  Virtual machine execution is not allowed
	condition:
		any of ($a_*)
 
}