
rule TrojanDownloader_BAT_AsyncRAT_BH_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {00 00 01 a2 14 28 ?? 00 00 0a 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 14 28 ?? 00 00 0a 06 1b 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 16 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a a2 14 16 17 28 } //2
		$a_01_1 = {47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73 00 } //1 GetExportedTypes
		$a_01_2 = {43 00 72 00 65 00 61 00 74 00 65 00 44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 } //1 CreateDelegate
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}