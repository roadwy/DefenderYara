
rule TrojanDownloader_Win32_Delf_ZBB{
	meta:
		description = "TrojanDownloader:Win32/Delf.ZBB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 77 69 6e 73 79 73 2e 62 61 74 } //1 \winsys.bat
		$a_00_1 = {5c 61 63 74 69 76 65 5f 75 72 6c 2e 64 6c 6c } //1 \active_url.dll
		$a_00_2 = {74 61 73 6b 6d 72 67 2e 65 78 65 } //1 taskmrg.exe
		$a_00_3 = {74 61 73 6b 69 6d 67 2e 65 78 65 } //1 taskimg.exe
		$a_00_4 = {4d 79 73 61 6d 70 6c 65 41 70 70 4d 75 74 65 78 5f 31 } //1 MysampleAppMutex_1
		$a_02_5 = {8d 44 24 04 50 e8 ?? ?? ?? ?? 8b c3 8b d4 b9 00 01 00 00 e8 ?? ?? ?? ?? 81 c4 00 01 00 00 5b c3 8b c0 55 8b ec 6a 00 6a 00 53 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? b9 ?? ?? ?? ?? b2 01 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*5) >=9
 
}