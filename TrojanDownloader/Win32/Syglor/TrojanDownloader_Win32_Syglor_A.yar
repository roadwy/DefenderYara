
rule TrojanDownloader_Win32_Syglor_A{
	meta:
		description = "TrojanDownloader:Win32/Syglor.A,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_02_0 = {be 0f 00 00 00 33 ff 52 89 b5 ?? ?? ?? ?? 89 bd ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 00 e8 } //10
		$a_00_1 = {26 68 61 72 64 69 64 3d 25 73 } //1 &hardid=%s
		$a_00_2 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5d } //1 \CurrentVersion\Run]
		$a_00_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4f 70 65 72 61 2f 39 2e 38 30 } //1 User-Agent: Opera/9.80
		$a_00_4 = {39 35 20 4f 53 52 20 32 } //1 95 OSR 2
		$a_00_5 = {31 32 33 2e 74 6d 70 } //1 123.tmp
		$a_00_6 = {2f 2e 73 79 73 2e 70 68 70 } //1 /.sys.php
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=15
 
}