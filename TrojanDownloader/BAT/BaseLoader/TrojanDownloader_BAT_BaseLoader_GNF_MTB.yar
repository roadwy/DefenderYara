
rule TrojanDownloader_BAT_BaseLoader_GNF_MTB{
	meta:
		description = "TrojanDownloader:BAT/BaseLoader.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {b7 17 d6 8d 90 01 04 13 06 08 11 06 16 08 6f 90 01 03 0a b7 6f 90 01 03 0a 26 28 90 01 03 0a 11 06 16 1a 6f 90 01 03 0a 0d 11 06 1a 28 90 01 03 0a 13 04 11 06 1e 28 90 01 03 0a 13 05 11 04 16 fe 01 11 05 16 fe 01 60 13 0a 11 0a 90 00 } //01 00 
		$a_80_1 = {75 69 5c 73 74 72 64 65 66 31 31 2e 62 69 6e } //ui\strdef11.bin  01 00 
		$a_01_2 = {41 69 6b 61 44 44 53 } //00 00  AikaDDS
	condition:
		any of ($a_*)
 
}