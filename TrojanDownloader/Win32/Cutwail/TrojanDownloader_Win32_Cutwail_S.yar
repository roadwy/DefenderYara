
rule TrojanDownloader_Win32_Cutwail_S{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.S,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 0f be 48 50 83 f9 69 75 07 b8 01 00 00 00 eb 02 33 c0 } //6
		$a_02_1 = {68 00 28 00 00 e8 ?? ?? ff ff 89 85 ?? fe ff ff 68 00 a0 0f 00 e8 ?? ?? ff ff 89 85 ?? fe ff ff a1 20 30 40 00 50 } //1
		$a_00_2 = {85 64 fe ff ff 50 8b 4d fc 51 8b 95 58 fe ff ff 52 8b 85 60 fe ff ff 8b 0c 85 24 30 40 00 51 } //1
		$a_01_3 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 30 } //1 \\.\PhysicalDrive0
		$a_01_4 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 \System32\svchost.exe
		$a_01_5 = {6d 75 74 61 6e 74 6f 66 74 68 65 66 75 74 75 72 65 } //1 mutantofthefuture
		$a_01_6 = {47 45 54 20 2f 34 30 } //1 GET /40
		$a_01_7 = {57 4c 45 76 65 6e 74 53 74 61 72 74 53 68 65 6c 6c } //1 WLEventStartShell
	condition:
		((#a_00_0  & 1)*6+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}