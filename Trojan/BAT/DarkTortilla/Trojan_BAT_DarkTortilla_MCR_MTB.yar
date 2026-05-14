
rule Trojan_BAT_DarkTortilla_MCR_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 00 20 00 6f 00 20 00 61 00 20 00 64 } //1
		$a_01_1 = {46 00 6f 00 63 00 75 00 73 00 46 00 6c 00 6f 00 77 } //1
		$a_01_2 = {75 00 73 00 65 00 72 00 2e 00 63 00 6f 00 6e 00 66 00 69 00 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}