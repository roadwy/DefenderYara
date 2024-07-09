
rule TrojanDownloader_Win32_Banload_HH{
	meta:
		description = "TrojanDownloader:Win32/Banload.HH,SIGNATURE_TYPE_PEHSTR_EXT,08 00 05 00 08 00 00 "
		
	strings :
		$a_03_0 = {81 3f 7b 73 6b 7d 74 ?? 8a 07 30 c8 28 e8 aa 4a 75 } //4
		$a_03_1 = {8b 45 fc 81 38 78 78 78 78 75 05 e9 ?? ?? 00 00 } //3
		$a_03_2 = {6a 00 6a 00 6a 06 e8 ?? ?? ?? ?? 50 68 ff 00 00 00 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 00 6a 00 6a 07 e8 ?? ?? ?? ?? 50 68 ff 00 00 00 } //2
		$a_01_3 = {25 77 69 6e 64 69 72 25 5c 44 6f 77 6e 6c 6f 61 64 65 64 20 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 67 62 } //1 %windir%\Downloaded Program Files\gb
		$a_01_4 = {25 70 72 6f 67 72 61 6d 66 69 6c 65 73 25 5c 47 62 50 6c 75 67 69 6e } //1 %programfiles%\GbPlugin
		$a_01_5 = {46 6f 6c 64 65 72 73 20 74 6f 20 64 65 6c 65 74 65 3a } //1 Folders to delete:
		$a_01_6 = {46 69 6c 65 73 20 74 6f 20 64 65 6c 65 74 65 3a } //1 Files to delete:
		$a_01_7 = {73 76 63 68 6f 73 74 2e 73 63 72 } //1 svchost.scr
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}