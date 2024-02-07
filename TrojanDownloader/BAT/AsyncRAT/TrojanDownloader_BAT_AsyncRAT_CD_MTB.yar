
rule TrojanDownloader_BAT_AsyncRAT_CD_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 } //01 00 
		$a_01_1 = {52 65 61 64 41 73 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 } //01 00  ReadAsByteArrayAsync
		$a_01_2 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}