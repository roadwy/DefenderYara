
rule TrojanDownloader_BAT_Tiny_NTD_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {73 06 00 00 0a 0a 06 72 90 01 03 70 6f 90 01 03 0a 06 72 90 01 03 70 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 28 90 01 03 0a 26 2a 90 00 } //05 00 
		$a_03_1 = {06 6a 20 00 00 00 80 6e 5f 20 90 01 03 80 6e 33 0c 06 17 62 20 90 01 03 04 61 0a 2b 04 06 17 62 0a 09 17 58 0d 09 1e 32 d7 90 00 } //01 00 
		$a_01_2 = {50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 79 6c 65 } //00 00  ProcessWindowStyle
	condition:
		any of ($a_*)
 
}