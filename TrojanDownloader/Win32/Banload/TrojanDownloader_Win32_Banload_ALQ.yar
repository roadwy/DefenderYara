
rule TrojanDownloader_Win32_Banload_ALQ{
	meta:
		description = "TrojanDownloader:Win32/Banload.ALQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f } //1 dl.dropbox.com/u/
		$a_03_1 = {ff b5 7c ff ff ff 8d 45 c4 ba 12 00 00 00 e8 ?? ?? ?? ?? 8b 45 c4 e8 ?? ?? ?? ?? 50 53 e8 ?? ?? ?? ?? 8b f8 } //1
		$a_03_2 = {8d 55 fc 33 c0 e8 ?? ?? ?? ?? ff 75 fc 8d 55 f8 33 c0 e8 ?? ?? ?? ?? ff 75 f8 } //1
		$a_03_3 = {6a 00 6a 00 8b 45 f8 e8 ?? ?? ?? ?? 50 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 ff d6 85 c0 0f 94 45 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}