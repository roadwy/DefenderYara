
rule TrojanDownloader_Win32_REntS_SIBF_MTB{
	meta:
		description = "TrojanDownloader:Win32/REntS.SIBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 17 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 6a 65 69 74 61 63 61 76 65 2e 6f 72 67 2f 31 32 55 32 32 6e 4f 4a 48 46 64 44 6d 59 63 67 43 53 2e 6a 70 67 } //10 http://jeitacave.org/12U22nOJHFdDmYcgCS.jpg
		$a_00_1 = {68 74 74 70 3a 2f 2f 6a 65 69 74 61 63 61 76 65 2e 6f 72 67 2f 75 61 63 2e 6a 70 67 } //10 http://jeitacave.org/uac.jpg
		$a_00_2 = {66 6f 75 6e 64 20 76 65 72 79 73 69 6c 65 6e 74 } //1 found verysilent
		$a_00_3 = {2f 76 65 72 79 73 69 6c 65 6e 74 } //1 /verysilent
		$a_00_4 = {7b 73 72 63 65 78 65 7d } //1 {srcexe}
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=23
 
}