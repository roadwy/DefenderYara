
rule TrojanDownloader_BAT_AsyncRAT_W_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 04 09 28 90 01 01 00 00 0a 13 05 28 90 01 01 00 00 0a 11 05 6f 90 01 01 00 00 0a 13 06 11 04 28 90 01 01 00 00 0a 13 07 28 90 01 01 00 00 0a 11 07 6f 90 01 01 00 00 0a 13 08 73 90 01 01 00 00 0a 06 28 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_3 = {4a 6f 69 6e } //01 00  Join
		$a_01_4 = {52 65 70 6c 61 63 65 } //00 00  Replace
	condition:
		any of ($a_*)
 
}