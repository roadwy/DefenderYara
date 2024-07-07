
rule TrojanDownloader_Win32_Doutrad_B{
	meta:
		description = "TrojanDownloader:Win32/Doutrad.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 14 06 32 d1 88 10 40 4f 75 f5 } //1
		$a_01_1 = {eb 16 6a 00 8d 4c 24 0c 6a 1a 51 6a 00 ff 15 } //1
		$a_01_2 = {b9 41 00 00 00 33 c0 8d 7c 24 08 6a ff f3 ab b9 41 00 00 00 8d bc 24 10 01 00 00 f3 ab } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}