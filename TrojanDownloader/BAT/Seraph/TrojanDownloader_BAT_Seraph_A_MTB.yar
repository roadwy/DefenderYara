
rule TrojanDownloader_BAT_Seraph_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/Seraph.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {61 d1 9d fe 90 01 03 20 90 01 04 20 02 90 01 03 63 20 90 01 04 58 66 20 02 90 01 03 62 20 90 01 04 59 66 20 90 01 04 59 59 25 90 00 } //01 00 
		$a_81_1 = {58 52 61 69 6c 73 } //01 00  XRails
		$a_81_2 = {43 6f 6e 73 6f 6c 65 41 70 70 } //01 00  ConsoleApp
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_6 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Seraph_A_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Seraph.A!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 1d 19 28 08 00 00 06 0a 06 19 16 28 08 00 00 06 0a 2b 22 0a 2b dc 0a 2b e6 72 01 00 00 70 06 28 06 00 00 06 8c 0d 00 00 01 28 15 00 00 0a 06 28 07 00 00 06 0a 06 28 09 00 00 06 16 fe 01 0b 07 2d d7 } //03 00 
		$a_01_1 = {fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 05 00 00 00 08 00 00 00 13 00 00 00 0b } //00 00 
	condition:
		any of ($a_*)
 
}