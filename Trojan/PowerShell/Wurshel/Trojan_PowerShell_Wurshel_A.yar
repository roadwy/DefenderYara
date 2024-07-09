
rule Trojan_PowerShell_Wurshel_A{
	meta:
		description = "Trojan:PowerShell/Wurshel.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 7a 00 78 00 63 00 69 00 75 00 6e 00 69 00 71 00 68 00 77 00 65 00 69 00 7a 00 73 00 64 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 } //1 .DownloadFile('http://zxciuniqhweizsds.com/
		$a_02_1 = {2e 00 63 00 6c 00 61 00 73 00 73 00 27 00 2c 00 20 00 24 00 65 00 6e 00 76 00 3a 00 41 00 50 00 50 00 44 00 41 00 54 00 41 00 20 00 2b 00 20 00 27 00 5c 00 5c 00 5c 00 [0-20] 2e 00 65 00 78 00 65 00 27 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}