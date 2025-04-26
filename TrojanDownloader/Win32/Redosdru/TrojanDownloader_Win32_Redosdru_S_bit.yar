
rule TrojanDownloader_Win32_Redosdru_S_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.S!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 6f 74 68 65 72 35 39 39 } //1 Kother599
		$a_03_1 = {8b 4d 08 03 4d ?? 0f b6 11 8b 45 0c 03 45 ?? 0f b6 08 33 ca 8b 55 0c 03 55 ?? 88 0a } //1
		$a_03_2 = {8b 55 08 03 55 ?? 8a 45 ?? 88 02 8b 45 ?? 33 d2 f7 75 10 8b 4d 0c 0f b6 14 11 8b 45 ?? 89 94 85 } //1
		$a_03_3 = {eb b0 c6 45 ?? 47 c6 45 ?? 65 c6 45 ?? 74 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 67 c6 45 ?? 35 c6 45 ?? 33 c6 45 ?? 38 c6 45 ?? 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}