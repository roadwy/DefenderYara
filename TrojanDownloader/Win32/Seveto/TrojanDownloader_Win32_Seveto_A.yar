
rule TrojanDownloader_Win32_Seveto_A{
	meta:
		description = "TrojanDownloader:Win32/Seveto.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 08 8b c8 8a 01 34 ?? 88 45 ?? 8b c1 8d 55 ?? b9 01 00 00 00 e8 ?? ?? ff ff 8b c3 25 ff 03 00 80 79 07 48 0d 00 fc ff ff 40 85 c0 75 07 6a ?? e8 ?? ?? ff ff 43 4e 75 } //1
		$a_03_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 8b 45 fc e8 ?? ?? ff ff 50 6a 00 6a 02 68 10 01 00 00 68 ff 01 0f 00 56 53 8b 45 f8 50 e8 ?? ?? ff ff 8b d8 33 c0 89 45 f4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}