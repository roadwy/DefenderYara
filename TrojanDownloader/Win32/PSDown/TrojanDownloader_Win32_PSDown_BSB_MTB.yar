
rule TrojanDownloader_Win32_PSDown_BSB_MTB{
	meta:
		description = "TrojanDownloader:Win32/PSDown.BSB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {28 00 5b 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74 00 5d 00 3a 00 3a 00 46 00 72 00 6f 00 6d 00 42 00 61 00 73 00 65 00 36 00 34 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 24 00 } //1 ([system.Convert]::FromBase64String($
		$a_00_1 = {2e 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 .Net.WebClient
		$a_00_2 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 44 00 61 00 74 00 61 00 28 00 } //1 .DownloadData(
		$a_00_3 = {5b 00 72 00 65 00 67 00 65 00 78 00 5d 00 3a 00 3a 00 73 00 70 00 6c 00 69 00 74 00 28 00 24 00 } //1 [regex]::split($
		$a_00_4 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 28 00 } //1 Invoke(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}