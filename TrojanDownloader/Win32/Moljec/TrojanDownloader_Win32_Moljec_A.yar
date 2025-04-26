
rule TrojanDownloader_Win32_Moljec_A{
	meta:
		description = "TrojanDownloader:Win32/Moljec.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 55 49 44 3d 25 49 36 34 75 26 42 55 49 4c 44 3d 25 73 26 49 4e 46 4f 3d 25 73 26 49 50 3d 25 73 26 54 59 50 45 3d 31 26 57 49 4e 3d 25 64 2e 25 64 28 78 36 34 29 } //1 GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(x64)
		$a_01_1 = {68 74 74 70 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 } //1 http://api.ipify.org
		$a_01_2 = {42 4e 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1
		$a_01_3 = {80 34 31 7a 41 3b c8 } //1
		$a_01_4 = {8b c1 83 e0 07 8a 04 30 30 04 31 41 3b ca 72 f0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}