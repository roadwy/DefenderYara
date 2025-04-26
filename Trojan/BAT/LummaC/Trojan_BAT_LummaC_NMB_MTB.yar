
rule Trojan_BAT_LummaC_NMB_MTB{
	meta:
		description = "Trojan:BAT/LummaC.NMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_01_1 = {02 11 15 9a 12 17 28 0e 01 00 0a 3a 4a 01 00 00 11 13 2c 0a 11 05 11 13 } //2
		$a_01_2 = {73 63 72 69 70 74 2e 70 73 31 } //1 script.ps1
		$a_01_3 = {a2 11 22 18 72 fc 03 00 70 a2 11 22 19 11 12 a2 11 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}