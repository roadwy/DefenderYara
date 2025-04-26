
rule TrojanDownloader_Win32_Hancitor_A_MTB{
	meta:
		description = "TrojanDownloader:Win32/Hancitor.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 28 78 36 34 29 } //1 GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)
		$a_01_1 = {52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 66 31 } //1 Rundll32.exe %s,f1
		$a_00_2 = {8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 0c 73 28 8b 45 fc 33 d2 b9 08 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c7 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}