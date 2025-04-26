
rule TrojanDownloader_Win32_Emuvito_A{
	meta:
		description = "TrojanDownloader:Win32/Emuvito.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 3b 58 75 f8 80 7b 01 58 75 f2 80 7b 02 58 75 ec 89 1d ?? ?? 42 00 a1 ?? ?? 42 00 83 78 14 00 0f 85 7b 03 00 00 a1 ?? ?? 42 00 8b 58 04 } //1
		$a_03_1 = {8a 10 80 f2 ?? 88 10 43 40 83 fb 0d 75 f2 } //1
		$a_03_2 = {8b d8 8a 83 ?? ?? 42 00 e8 ?? ?? ?? ff 3c 45 0f 84 dd 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}