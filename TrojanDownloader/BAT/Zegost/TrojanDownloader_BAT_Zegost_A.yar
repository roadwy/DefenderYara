
rule TrojanDownloader_BAT_Zegost_A{
	meta:
		description = "TrojanDownloader:BAT/Zegost.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 61 00 78 00 31 00 32 00 33 00 34 00 } //1 max1234
		$a_02_1 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 31 00 32 00 33 00 34 00 2e 00 6d 00 69 00 72 00 65 00 65 00 6e 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 2f 00 68 00 74 00 6d 00 6c 00 2f 00 [0-10] 2e 00 65 00 78 00 65 00 } //1
		$a_00_2 = {63 00 3a 00 2f 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2f 00 73 00 79 00 73 00 2e 00 69 00 6e 00 69 00 } //1 c:/windows/sys.ini
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}