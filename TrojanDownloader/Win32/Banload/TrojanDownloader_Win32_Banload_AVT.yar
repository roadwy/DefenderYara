
rule TrojanDownloader_Win32_Banload_AVT{
	meta:
		description = "TrojanDownloader:Win32/Banload.AVT,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {61 6c 72 65 61 64 72 79 63 6f 6d 70 61 72 65 70 72 69 63 65 73 70 6f 70 75 6c 61 72 65 61 72 68 } //1 alreadrycomparepricespopularearh
		$a_01_1 = {6b 69 64 69 6e 6c 68 61 74 69 6e 61 66 6f 72 6d 65 6d 2d 73 6f 6c 74 6c 61 76 69 6e } //1 kidinlhatinaformem-soltlavin
		$a_03_2 = {5c 52 75 6e 90 01 0a 55 73 65 72 50 72 6f 66 69 6c 65 90 00 } //1
		$a_03_3 = {36 34 2e 65 78 65 90 0a 15 00 61 73 77 90 00 } //1
		$a_01_4 = {47 65 74 50 43 4e 61 6d 65 } //1 GetPCName
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}