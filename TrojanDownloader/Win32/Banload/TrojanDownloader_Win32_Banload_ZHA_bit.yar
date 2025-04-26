
rule TrojanDownloader_Win32_Banload_ZHA_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZHA!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {b9 01 00 00 00 8b c6 8b 38 ff 57 0c 8b 4d ec 0f b7 45 e8 d3 e8 f6 d0 30 45 eb 8d 55 eb b9 01 00 00 00 8b 45 f0 8b 38 ff 57 10 ff 45 ec 4b 75 cd } //1
		$a_03_1 = {6a 04 68 00 10 00 00 8b 45 fc 50 8b 45 f8 03 43 0c 50 e8 ?? ?? ?? ?? 8b f0 89 73 08 8b 55 fc 8b c6 [0-20] 6a 04 68 00 10 00 00 8b 43 10 50 8b 45 f8 03 43 0c 50 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}