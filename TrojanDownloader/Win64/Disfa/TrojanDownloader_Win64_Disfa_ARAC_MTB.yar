
rule TrojanDownloader_Win64_Disfa_ARAC_MTB{
	meta:
		description = "TrojanDownloader:Win64/Disfa.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {3a 2f 2f 77 65 74 68 73 6a 6a 73 64 66 2e 73 65 72 76 65 6d 69 6e 65 63 72 61 66 74 2e 6e 65 74 2f 90 02 3f 2e 65 78 65 90 00 } //2
		$a_01_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //2 URLDownloadToFile
		$a_01_2 = {25 41 5f 53 74 61 72 74 75 70 25 } //2 %A_Startup%
		$a_80_3 = {26 57 69 6e 64 6f 77 20 53 70 79 } //&Window Spy  2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_80_3  & 1)*2) >=8
 
}