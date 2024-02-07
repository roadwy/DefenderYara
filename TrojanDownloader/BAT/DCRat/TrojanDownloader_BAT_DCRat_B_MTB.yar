
rule TrojanDownloader_BAT_DCRat_B_MTB{
	meta:
		description = "TrojanDownloader:BAT/DCRat.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 07 03 fe 90 01 01 16 fe 90 01 01 0d 09 2d 90 01 01 06 28 90 01 03 2b 17 8d 90 01 03 01 6f 90 01 03 0a 13 90 01 01 2b 90 01 01 11 90 01 01 2a 90 0a 52 00 03 17 58 8d 90 01 03 01 0a 16 0b 2b 90 01 01 00 00 06 07 02 07 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 9d 00 de 90 01 01 0c 00 de 90 01 01 00 07 17 58 90 00 } //01 00 
		$a_03_1 = {0b 07 02 6f 90 0a 28 00 02 2c 90 01 01 20 90 01 03 81 0a 16 0b 2b 90 01 01 02 07 6f 90 01 03 0a 06 61 20 90 01 03 01 5a 0a 07 17 58 90 00 } //01 00 
		$a_03_2 = {00 03 04 05 0e 04 28 90 01 01 00 00 0a 00 2a 90 00 } //01 00 
		$a_01_3 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_4 = {46 6c 75 73 68 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  FlushFinalBlock
		$a_01_5 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_6 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //00 00  RijndaelManaged
	condition:
		any of ($a_*)
 
}