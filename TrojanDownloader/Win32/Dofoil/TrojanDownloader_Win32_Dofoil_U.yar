
rule TrojanDownloader_Win32_Dofoil_U{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.U,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 07 00 00 "
		
	strings :
		$a_01_0 = {32 28 c1 c1 08 32 cd 40 80 38 00 75 f3 } //1
		$a_01_1 = {66 c7 07 57 6f 66 c7 47 02 72 6b } //1
		$a_01_2 = {ac 32 c2 aa e2 fa } //1
		$a_01_3 = {c7 45 fc 43 3a 5c 00 8d 45 fc 8d 4d f8 56 56 56 56 51 68 80 00 00 00 56 50 ff 15 } //1
		$a_01_4 = {83 c0 04 8b 00 89 45 fc 8b 45 fc 35 de c0 ad de } //1
		$a_01_5 = {8a 1b 32 1e 88 5c 24 04 2a 4c 24 04 33 db 8a d8 03 1c 24 4b 88 0b } //1
		$a_03_6 = {b8 5a 00 00 00 e8 44 90 01 04 04 20 88 04 37 46 4b 75 ed 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=3
 
}