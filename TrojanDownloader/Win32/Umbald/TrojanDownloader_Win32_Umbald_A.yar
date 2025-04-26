
rule TrojanDownloader_Win32_Umbald_A{
	meta:
		description = "TrojanDownloader:Win32/Umbald.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {6d 00 6f 00 64 00 65 00 3d 00 [0-02] 26 00 55 00 49 00 44 00 3d 00 00 } //1
		$a_03_1 = {6d 6f 64 65 3d [0-02] 26 55 49 44 3d 00 } //1
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 26 45 78 65 63 75 74 65 00 } //1
		$a_81_3 = {50 6c 75 67 69 6e 53 74 61 72 74 00 } //1 汐杵湩瑓牡t
		$a_81_4 = {2f 50 61 6e 65 6c 2f 62 6f 74 2e 70 68 70 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=3
 
}