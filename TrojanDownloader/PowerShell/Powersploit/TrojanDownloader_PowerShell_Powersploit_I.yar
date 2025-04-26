
rule TrojanDownloader_PowerShell_Powersploit_I{
	meta:
		description = "TrojanDownloader:PowerShell/Powersploit.I,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 28 00 [0-80] 2f 00 6d 00 61 00 74 00 74 00 69 00 66 00 65 00 73 00 74 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 70 00 6f 00 77 00 65 00 72 00 73 00 70 00 6c 00 6f 00 69 00 74 00 2f 00 6d 00 61 00 73 00 74 00 65 00 72 00 2f 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}