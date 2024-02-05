
rule Trojan_Win32_IcedId_AB_MTB{
	meta:
		description = "Trojan:Win32/IcedId.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {57 61 72 63 6f 20 20 6c 65 67 67 75 } //Warco  leggu  03 00 
		$a_80_1 = {4c 6f 63 61 6c 65 4e 61 6d 65 54 6f 4c 43 49 44 } //LocaleNameToLCID  03 00 
		$a_80_2 = {48 61 69 72 5c 54 69 65 72 61 6e 67 65 2e 70 64 62 } //Hair\Tierange.pdb  03 00 
		$a_80_3 = {73 6f 6d 65 5c 75 73 5c 53 65 65 5c 74 68 61 6e 6b } //some\us\See\thank  03 00 
		$a_80_4 = {47 65 74 45 6e 76 69 72 6f 6e 6d 65 6e 74 56 61 72 69 61 62 6c 65 57 } //GetEnvironmentVariableW  03 00 
		$a_80_5 = {47 65 74 54 65 78 74 4d 65 74 72 69 63 73 57 } //GetTextMetricsW  03 00 
		$a_80_6 = {6f 72 64 36 35 38 32 } //ord6582  00 00 
	condition:
		any of ($a_*)
 
}