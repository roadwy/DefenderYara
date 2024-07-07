
rule TrojanDownloader_PowerShell_Gripogle_A{
	meta:
		description = "TrojanDownloader:PowerShell/Gripogle.A,SIGNATURE_TYPE_CMDHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //10 powershell.exe
		$a_00_1 = {2f 00 2f 00 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00 } //10 //iplogger.org/
		$a_00_2 = {62 00 69 00 74 00 73 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 } //1 bitstransfer
		$a_00_3 = {6e 00 65 00 77 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 new-object
		$a_00_4 = {69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00 77 00 65 00 62 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 } //1 invoke-webrequest
		$a_00_5 = {3a 00 3a 00 72 00 65 00 66 00 6c 00 65 00 63 00 74 00 } //1 ::reflect
		$a_00_6 = {3a 00 3a 00 6c 00 6f 00 61 00 64 00 } //1 ::load
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=21
 
}