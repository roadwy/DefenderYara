
rule TrojanDownloader_Win32_Chaneeks_A{
	meta:
		description = "TrojanDownloader:Win32/Chaneeks.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 86 57 0d 00 68 88 4e 0d 00 e8 1a 00 00 00 89 45 fc 68 fa 8b 34 00 68 88 4e 0d 00 } //1
		$a_03_1 = {8d 44 24 04 8d 4c 24 00 50 51 e8 ?? ?? ff ff 83 c4 08 68 ?? ?? ?? ?? ff 54 24 04 68 ?? ?? ?? ?? 89 44 24 ?? ff 54 24 04 68 ?? ?? ?? ?? 50 89 44 24 ?? ff 54 24 0c 8b 54 24 ?? 68 ?? ?? ?? ?? 52 89 44 24 ?? ff 54 24 0c 89 44 24 ?? 8d 44 24 00 50 e8 ?? ?? ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}