
rule Trojan_PowerShell_PowDow_DD_MTB{
	meta:
		description = "Trojan:PowerShell/PowDow.DD!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 [0-50] 24 00 } //1
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 } //1 $env:
		$a_00_2 = {2e 00 28 00 67 00 61 00 6c 00 20 00 2a 00 65 00 78 00 29 00 28 00 26 00 28 00 67 00 63 00 6d 00 20 00 2a 00 65 00 73 00 74 00 4d 00 2a 00 29 00 } //1 .(gal *ex)(&(gcm *estM*)
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}