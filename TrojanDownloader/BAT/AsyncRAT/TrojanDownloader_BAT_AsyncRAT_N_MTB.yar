
rule TrojanDownloader_BAT_AsyncRAT_N_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 ff ff 00 00 0a 02 6f 90 01 01 00 00 0a 0b 16 0c 90 00 } //01 00 
		$a_03_1 = {07 08 93 28 90 01 01 00 00 06 90 01 01 59 0d 06 09 90 00 } //01 00 
		$a_01_2 = {09 06 59 0d 2b } //01 00 
		$a_01_3 = {07 08 09 d1 9d 08 17 58 0c 08 07 8e 69 } //01 00 
		$a_01_4 = {00 00 04 20 00 01 00 00 14 14 03 74 } //01 00 
		$a_01_5 = {47 65 74 54 79 70 65 } //01 00 
		$a_01_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}