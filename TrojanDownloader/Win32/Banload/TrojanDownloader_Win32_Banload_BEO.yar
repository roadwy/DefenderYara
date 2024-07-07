
rule TrojanDownloader_Win32_Banload_BEO{
	meta:
		description = "TrojanDownloader:Win32/Banload.BEO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {be 01 00 00 00 8b 45 ec 33 db 8a 5c 30 ff 33 5d e4 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 } //1
		$a_01_1 = {44 43 36 44 38 33 41 30 41 39 31 30 34 36 45 32 } //1 DC6D83A0A91046E2
		$a_01_2 = {42 35 37 38 38 38 41 42 35 36 38 39 43 36 42 32 41 38 45 34 37 41 41 32 34 39 } //1 B57888AB5689C6B2A8E47AA249
		$a_03_3 = {31 7c 00 00 90 01 08 32 7c 00 00 90 01 08 33 7c 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}