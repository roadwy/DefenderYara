
rule TrojanDownloader_BAT_Androm_AND_MTB{
	meta:
		description = "TrojanDownloader:BAT/Androm.AND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 06 07 6f 90 01 01 00 00 0a 72 90 01 01 01 00 70 28 90 01 01 00 00 0a 11 06 08 09 6f 90 01 01 00 00 0a 72 90 01 01 01 00 70 28 90 01 01 00 00 0a 11 06 11 04 11 05 90 00 } //2
		$a_01_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 32 00 32 00 39 00 63 00 73 00 2e 00 70 00 73 00 31 00 } //1 C:\Users\Public\229cs.ps1
		$a_01_2 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 20 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 64 00 } //1 PowerShell command executed
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}