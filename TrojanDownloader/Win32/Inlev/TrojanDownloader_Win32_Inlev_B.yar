
rule TrojanDownloader_Win32_Inlev_B{
	meta:
		description = "TrojanDownloader:Win32/Inlev.B,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 bd b5 b8 8f 90 02 40 e8 90 01 04 59 59 ff d0 90 00 } //10
		$a_03_1 = {68 5b bc 4a 6a c7 84 24 90 01 02 00 00 77 73 32 5f c7 84 24 90 01 02 00 00 33 32 2e 64 c7 84 24 90 01 02 00 00 6c 6c 00 00 e8 90 00 } //1
		$a_03_2 = {68 64 77 79 0e 90 02 18 c7 90 01 01 48 54 54 50 90 00 } //1
		$a_03_3 = {68 26 80 ac c8 90 02 04 c7 44 24 90 01 01 77 73 32 5f c7 44 24 90 01 01 33 32 2e 64 c7 44 24 90 01 01 6c 6c 00 00 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=11
 
}