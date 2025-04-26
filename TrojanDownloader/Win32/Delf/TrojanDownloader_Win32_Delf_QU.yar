
rule TrojanDownloader_Win32_Delf_QU{
	meta:
		description = "TrojanDownloader:Win32/Delf.QU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 5c 46 2e 65 78 65 } //1 C:\WINDOWS\system\F.exe
		$a_03_1 = {8d 45 f8 ba ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 55 f8 8b 83 0c 03 00 00 8b ce e8 ?? ?? ?? ff 8b c6 e8 ?? ?? ?? ff 8b 83 ?? 03 00 00 b2 01 e8 ?? ?? ?? ff 6a 05 68 ?? ?? ?? 00 e8 ?? ?? ?? ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}