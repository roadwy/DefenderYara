
rule TrojanDownloader_Win32_Alureon_C{
	meta:
		description = "TrojanDownloader:Win32/Alureon.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 65 78 65 3b 68 74 74 70 3a 2f 2f } //1 .exe;http://
		$a_01_1 = {61 6c 6c 6f 77 65 64 70 72 6f 67 72 61 6d 20 25 73 20 65 6e 61 62 6c 65 } //1 allowedprogram %s enable
		$a_03_2 = {68 80 96 98 00 6a 40 ff 15 ?? ?? ?? 00 8d 4d ?? 51 68 40 54 89 00 50 53 } //1
		$a_03_3 = {0f 31 83 e0 0a 89 45 ?? 8b 45 ?? 69 c0 e8 03 00 00 50 ff 15 } //2
		$a_01_4 = {80 3b 3b 74 0c ff 45 fc 8b 45 fc 80 3c 18 3b 75 f4 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2) >=4
 
}