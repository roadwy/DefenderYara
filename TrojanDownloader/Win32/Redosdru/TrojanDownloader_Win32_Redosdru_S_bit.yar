
rule TrojanDownloader_Win32_Redosdru_S_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.S!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4b 6f 74 68 65 72 35 39 39 } //01 00 
		$a_03_1 = {8b 4d 08 03 4d 90 01 01 0f b6 11 8b 45 0c 03 45 90 01 01 0f b6 08 33 ca 8b 55 0c 03 55 90 01 01 88 0a 90 00 } //01 00 
		$a_03_2 = {8b 55 08 03 55 90 01 01 8a 45 90 01 01 88 02 8b 45 90 01 01 33 d2 f7 75 10 8b 4d 0c 0f b6 14 11 8b 45 90 01 01 89 94 85 90 00 } //01 00 
		$a_03_3 = {eb b0 c6 45 90 01 01 47 c6 45 90 01 01 65 c6 45 90 01 01 74 c6 45 90 01 01 6f c6 45 90 01 01 6e c6 45 90 01 01 67 c6 45 90 01 01 35 c6 45 90 01 01 33 c6 45 90 01 01 38 c6 45 90 01 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}