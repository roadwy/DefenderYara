
rule TrojanDownloader_BAT_Balamid_A{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 74 61 73 6b 31 36 2e 63 6f 6d } //wintask16.com  1
		$a_80_1 = {5c 6c 73 6d 2e 65 78 65 } //\lsm.exe  1
		$a_80_2 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  1
		$a_80_3 = {2f 65 78 63 32 2e 74 78 74 } ///exc2.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule TrojanDownloader_BAT_Balamid_A_2{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 74 61 73 6b 33 32 2e 63 6f 6d } //wintask32.com  1
		$a_80_1 = {5c 6c 73 6d 2e 65 78 65 } //\lsm.exe  1
		$a_80_2 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  1
		$a_80_3 = {2f 65 78 63 32 2e 74 78 74 } ///exc2.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule TrojanDownloader_BAT_Balamid_A_3{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 74 61 73 6b 36 34 2e 63 6f 6d } //wintask64.com  1
		$a_80_1 = {5c 6c 73 6d 2e 65 78 65 } //\lsm.exe  1
		$a_80_2 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  1
		$a_80_3 = {2f 65 78 63 32 2e 74 78 74 } ///exc2.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}
rule TrojanDownloader_BAT_Balamid_A_4{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {77 77 77 2e 77 69 6e 74 61 73 6b 90 0f 02 00 2e 63 6f 6d } //1
		$a_02_1 = {77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 90 0f 01 00 00 90 0f 01 00 00 2e 00 63 00 6f 00 6d 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule TrojanDownloader_BAT_Balamid_A_5{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {77 69 6e 74 61 73 6b 36 34 2e 63 6f 6d } //wintask64.com  1
		$a_80_1 = {5c 74 61 73 6b 36 34 2e 65 78 65 } //\task64.exe  1
		$a_80_2 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  1
		$a_80_3 = {2f 74 6f 79 32 2e 74 78 74 } ///toy2.txt  1
		$a_80_4 = {5c 6c 73 6d 2e 65 78 65 } //\lsm.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}
rule TrojanDownloader_BAT_Balamid_A_6{
	meta:
		description = "TrojanDownloader:BAT/Balamid.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {5c 6c 73 6d 2e 65 78 65 } //\lsm.exe  1
		$a_80_1 = {62 61 67 6c 61 6e 6d 61 64 69 } //baglanmadi  1
		$a_80_2 = {77 69 6e 74 61 73 6b 36 34 2e 63 6f 6d } //wintask64.com  2
		$a_80_3 = {2f 65 78 63 32 2e 74 78 74 } ///exc2.txt  1
		$a_80_4 = {2f 64 6c 2e 74 78 74 } ///dl.txt  1
		$a_80_5 = {2f 75 72 6c 2e 74 78 74 } ///url.txt  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}