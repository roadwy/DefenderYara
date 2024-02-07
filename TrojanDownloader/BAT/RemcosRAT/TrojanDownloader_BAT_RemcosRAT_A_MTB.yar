
rule TrojanDownloader_BAT_RemcosRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/RemcosRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 0a 0d 06 09 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 16 2d cf 18 2c cc 00 06 6f 90 01 01 00 00 0a 02 16 02 8e 69 6f 90 01 01 00 00 0a 10 00 02 13 04 de 2c 28 90 01 01 00 00 0a 2b af 6f 90 01 01 00 00 0a 2b af 0b 2b ae 73 90 01 01 00 00 0a 2b a9 0c 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_2 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_01_3 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //01 00  GetResponseStream
		$a_01_6 = {4e 65 78 74 42 79 74 65 73 } //00 00  NextBytes
	condition:
		any of ($a_*)
 
}