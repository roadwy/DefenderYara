
rule TrojanDownloader_Win32_Dogrobot_C{
	meta:
		description = "TrojanDownloader:Win32/Dogrobot.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 4d 0c 31 06 46 e2 fb 8b fa 83 c9 ff 33 c0 8b 5d 10 } //1
		$a_01_1 = {8a 0e 8a 10 2a d1 88 10 8a ca 8a 16 32 d1 46 88 10 40 4f 75 e4 } //1
		$a_01_2 = {25 73 25 64 5f 78 65 65 78 2e 65 78 65 } //1 %s%d_xeex.exe
		$a_01_3 = {6a 00 8d 54 24 18 68 04 01 00 00 52 57 56 ff 15 90 01 04 85 c0 75 0c } //1
		$a_01_4 = {63 6f 75 6e 74 2e 61 73 70 3f 6d 61 63 3d } //1 count.asp?mac=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}