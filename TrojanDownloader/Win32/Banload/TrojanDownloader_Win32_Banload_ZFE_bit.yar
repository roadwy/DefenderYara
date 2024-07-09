
rule TrojanDownloader_Win32_Banload_ZFE_bit{
	meta:
		description = "TrojanDownloader:Win32/Banload.ZFE!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 45 f0 8b 55 fc 0f b7 54 5a fe e8 ?? ?? ?? ff ff 75 f0 8d 45 ec 8b 55 fc 0f b7 14 5a e8 ?? ?? ?? ff ff 75 ec 8d 45 f4 ba 03 00 00 00 e8 ?? ?? ?? ff 8b 45 f4 e8 ?? ?? ?? ff 2a 05 ?? ?? ?? 00 8b 55 f8 88 04 32 83 c3 02 46 3b fb 7f ad } //2
		$a_03_1 = {6a 40 68 00 30 00 00 53 6a 00 e8 ?? ?? ?? ff 8b f0 85 f6 74 78 8b cb 8b d6 8b 45 fc e8 ?? ?? ?? ff } //1
		$a_03_2 = {b9 00 00 00 00 e8 ?? ?? ?? ff 8b 45 d8 e8 ?? ?? ?? ff 50 68 ?? ?? ?? 00 68 ?? ?? ?? 00 ff d3 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}