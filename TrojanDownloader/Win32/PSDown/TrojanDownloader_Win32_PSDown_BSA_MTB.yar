
rule TrojanDownloader_Win32_PSDown_BSA_MTB{
	meta:
		description = "TrojanDownloader:Win32/PSDown.BSA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 24 00 } //1 -command $
		$a_02_1 = {2d 00 6a 00 6f 00 69 00 6e 00 20 00 24 00 [0-20] 5b 00 2d 00 31 00 2e 00 2e 00 2d 00 28 00 24 00 [0-20] 2e 00 6c 00 65 00 6e 00 67 00 74 00 68 00 29 00 5d 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}