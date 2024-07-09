
rule TrojanDownloader_Win32_Banload_AQY{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQY,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 55 df 88 54 30 ff 46 4f 75 c1 } //1
		$a_03_1 = {8b 00 8b 08 ff 51 38 8d 45 ?? 50 8b 0e 8b 13 b8 ?? ?? ?? 00 e8 ?? ?? 00 00 8b 55 ?? a1 ?? ?? ?? 00 8b 00 8b 08 ff 51 38 8d 45 ?? 50 8b 0e 8b 13 b8 ?? ?? ?? 00 e8 ?? ?? 00 00 8b 55 ?? a1 ?? ?? ?? 00 8b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}