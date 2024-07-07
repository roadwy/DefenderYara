
rule TrojanDownloader_Win32_Brantall_D{
	meta:
		description = "TrojanDownloader:Win32/Brantall.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 0e 88 59 90 01 01 b9 90 01 04 2b c8 8b d7 8a 1c 01 80 f3 90 01 01 88 18 40 4a 75 f4 57 8b ce 90 00 } //1
		$a_01_1 = {72 63 34 28 31 78 2c 63 68 61 72 29 00 } //1
		$a_01_2 = {2d 00 6e 00 6f 00 64 00 65 00 63 00 00 00 00 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}