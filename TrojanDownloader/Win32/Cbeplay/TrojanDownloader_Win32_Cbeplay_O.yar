
rule TrojanDownloader_Win32_Cbeplay_O{
	meta:
		description = "TrojanDownloader:Win32/Cbeplay.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {25 73 26 71 38 3d 25 64 26 70 61 79 6c 6f 61 64 3d 25 73 } //1 %s&q8=%d&payload=%s
		$a_00_1 = {25 73 26 76 65 72 3d 25 75 2e 25 75 2e 25 75 2e 25 75 26 6f 73 3d 25 75 26 69 64 78 3d 25 75 } //1 %s&ver=%u.%u.%u.%u&os=%u&idx=%u
		$a_02_2 = {5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 [0-05] 73 76 63 68 6f 73 74 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}