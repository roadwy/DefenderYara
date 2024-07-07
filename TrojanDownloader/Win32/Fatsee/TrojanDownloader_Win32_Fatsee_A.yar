
rule TrojanDownloader_Win32_Fatsee_A{
	meta:
		description = "TrojanDownloader:Win32/Fatsee.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 6b 76 73 79 73 } //1 \\.\kvsys
		$a_01_1 = {26 79 3d 00 3f 78 3d 00 44 4c 00 00 2e 69 6e 69 } //1
		$a_01_2 = {8d 44 24 10 50 b3 6c 51 c6 44 24 18 69 c6 44 24 19 65 c6 44 24 1b 70 88 5c 24 1c c6 44 24 1d 6f c6 44 24 1e 72 c6 44 24 1f 65 c6 44 24 20 2e c6 44 24 21 65 c6 44 24 23 65 c6 44 24 24 00 ff 15 d4 30 00 25 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}