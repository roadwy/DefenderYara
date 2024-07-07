
rule TrojanDownloader_Win32_Blz_A{
	meta:
		description = "TrojanDownloader:Win32/Blz.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 68 43 32 33 70 53 64 61 5a 4d 64 4d 76 46 48 31 66 65 33 35 7a 77 4f 43 75 77 00 6e 74 64 6c 6c 2e 64 6c 6c } //1
		$a_01_1 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 38 00 25 61 70 70 64 61 74 61 25 } //1
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //1 InternetOpenUrlA
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
		$a_01_4 = {68 d4 31 40 00 50 ff 15 18 20 40 00 56 56 56 6a 01 68 14 31 40 00 ff 15 20 32 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}