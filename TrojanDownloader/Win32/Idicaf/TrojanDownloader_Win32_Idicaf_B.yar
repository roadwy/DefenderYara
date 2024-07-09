
rule TrojanDownloader_Win32_Idicaf_B{
	meta:
		description = "TrojanDownloader:Win32/Idicaf.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 83 fb 0c 74 21 6a 00 8d 55 ?? b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ?? e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 85 c0 74 c6 } //1
		$a_03_1 = {8d 44 18 ff 50 8b c3 b9 0a 00 00 00 99 f7 f9 8a 82 ?? ?? ?? ?? 8a 54 1f ff 32 c2 5a 88 02 43 4e 75 d7 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}