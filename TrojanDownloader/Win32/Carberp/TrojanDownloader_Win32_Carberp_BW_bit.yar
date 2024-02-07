
rule TrojanDownloader_Win32_Carberp_BW_bit{
	meta:
		description = "TrojanDownloader:Win32/Carberp.BW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 1e 0f b6 06 80 e3 1f 33 f8 0f b6 cb d3 c7 8d 76 02 33 c0 66 39 06 75 e7 } //01 00 
		$a_01_1 = {8a 6d 10 8d 58 01 0f b6 c3 89 45 fc 8b f8 8a 0c 10 02 e9 0f b6 c5 89 45 10 8a 04 10 88 04 17 8b 45 10 88 0c 10 8a 04 17 8b 7d 08 02 c1 0f b6 c0 8a 04 10 30 04 3e 46 8b 45 fc 3b 75 0c 7c c1 } //01 00 
		$a_01_2 = {76 6e 63 64 6c 6c 33 32 2e 64 6c 6c 00 56 6e 63 53 74 61 72 74 53 65 72 76 65 72 00 56 6e 63 53 74 6f 70 53 65 72 76 65 72 00 } //00 00  湶摣汬㈳搮汬嘀据瑓牡却牥敶r湖卣潴印牥敶r
	condition:
		any of ($a_*)
 
}