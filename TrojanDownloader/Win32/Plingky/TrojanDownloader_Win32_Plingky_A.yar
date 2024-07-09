
rule TrojanDownloader_Win32_Plingky_A{
	meta:
		description = "TrojanDownloader:Win32/Plingky.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c7 44 24 04 00 00 00 10 89 34 24 e8 ?? ?? ?? ?? 83 ec 1c 89 c2 83 f8 ff 74 77 31 c0 83 c9 ff 89 df f2 ae f7 d1 49 c7 44 24 10 00 00 00 00 8d 45 e4 89 44 24 0c 89 4c 24 08 89 5c 24 04 89 14 24 89 95 d4 fc ff ff e8 ?? ?? ?? ?? 83 ec 14 8b 95 d4 fc ff ff } //1
		$a_02_1 = {c7 44 24 14 00 00 00 00 c7 44 24 10 00 00 00 00 c7 44 24 0c ?? ?? ?? ?? 89 74 24 08 c7 44 24 04 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 83 ec 18 8d 65 f4 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}