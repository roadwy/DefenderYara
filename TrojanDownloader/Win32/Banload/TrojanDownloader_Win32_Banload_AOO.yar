
rule TrojanDownloader_Win32_Banload_AOO{
	meta:
		description = "TrojanDownloader:Win32/Banload.AOO,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {64 89 20 8d 55 f4 b8 1c 00 00 00 e8 ?? ?? ?? ?? 8d 45 f0 8b 55 f4 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 fc ba 03 00 00 00 e8 ?? ?? ?? ?? ff 75 f0 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 f8 ba 03 00 00 00 } //1
		$a_03_1 = {84 c0 75 1b 8b 55 fc b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a 33 d2 8b 45 fc e8 ?? ?? ?? ?? 8b 45 f8 e8 ?? ?? ?? ?? 84 c0 75 1b 8b 55 f8 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 84 c0 74 0a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}