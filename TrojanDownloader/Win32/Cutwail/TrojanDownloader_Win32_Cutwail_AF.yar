
rule TrojanDownloader_Win32_Cutwail_AF{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {31 03 83 e9 04 7e 14 8d 3c 32 03 c7 03 45 f8 8d 9b 90 01 04 03 de f7 da eb e5 90 00 } //2
		$a_01_1 = {f7 d9 41 6a 00 83 ca 05 51 ff 10 c9 c3 } //1
		$a_01_2 = {81 c1 fa 0b 00 00 8d 45 ec 50 b8 30 00 00 00 e8 } //1
		$a_01_3 = {01 03 2b ca 03 0b 51 ff 13 } //1
		$a_01_4 = {52 65 73 65 74 57 72 69 74 65 57 61 74 63 68 } //1 ResetWriteWatch
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}