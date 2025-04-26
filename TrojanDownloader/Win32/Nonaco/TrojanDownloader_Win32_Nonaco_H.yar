
rule TrojanDownloader_Win32_Nonaco_H{
	meta:
		description = "TrojanDownloader:Win32/Nonaco.H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {6a 03 5f 8d 8c 05 ?? ?? ff ff 99 f7 ff 28 11 ff 45 90 09 05 00 73 12 8b 45 } //2
		$a_03_1 = {8d 55 e6 8b c1 8b f7 8b fa c6 45 ?? 75 c1 e9 02 c6 45 ?? 72 c6 45 ?? 6c c6 45 ?? 63 } //2
		$a_03_2 = {74 04 6a 01 eb 19 8d 85 00 fc ff ff 68 ?? ?? ?? ?? 50 e8 ?? ?? ff ff 59 84 c0 59 74 05 6a 02 58 eb 03 } //2
		$a_01_3 = {70 69 64 3d 25 73 26 73 3d 25 73 26 76 3d 25 73 26 75 73 65 72 3d 25 73 } //1 pid=%s&s=%s&v=%s&user=%s
		$a_01_4 = {49 6e 76 6f 6b 65 20 64 69 73 70 69 64 20 3d 20 25 64 } //1 Invoke dispid = %d
		$a_01_5 = {65 34 30 35 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}