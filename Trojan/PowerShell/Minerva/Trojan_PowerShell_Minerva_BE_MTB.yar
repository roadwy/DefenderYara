
rule Trojan_PowerShell_Minerva_BE_MTB{
	meta:
		description = "Trojan:PowerShell/Minerva.BE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 00 20 00 27 00 73 00 69 00 6c 00 65 00 6e 00 74 00 6c 00 79 00 63 00 6f 00 6e 00 74 00 69 00 6e 00 75 00 65 00 27 00 } //1 = 'silentlycontinue'
		$a_00_1 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 } //1 .DownloadFile('http
		$a_00_2 = {2e 00 65 00 78 00 65 00 27 00 2c 00 20 00 27 00 63 00 3a 00 } //1 .exe', 'c:
		$a_00_3 = {73 00 54 00 61 00 72 00 74 00 2d 00 70 00 52 00 6f 00 43 00 45 00 73 00 73 00 20 00 27 00 63 00 3a 00 } //1 sTart-pRoCEss 'c:
		$a_00_4 = {49 00 6e 00 76 00 6f 00 69 00 63 00 65 00 2e 00 65 00 58 00 45 00 } //1 Invoice.eXE
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}