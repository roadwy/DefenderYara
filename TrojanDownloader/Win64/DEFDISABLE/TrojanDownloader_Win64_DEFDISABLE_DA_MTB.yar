
rule TrojanDownloader_Win64_DEFDISABLE_DA_MTB{
	meta:
		description = "TrojanDownloader:Win64/DEFDISABLE.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e } //1 Add-MpPreference -ExclusionExtension
		$a_81_1 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_03_2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-0f] 2e 00 65 00 78 00 65 00 } //1
		$a_03_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c [0-0f] 2e 65 78 65 } //1
		$a_81_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}