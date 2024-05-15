
rule Trojan_BAT_WebShell_HNG_MTB{
	meta:
		description = "Trojan:BAT/WebShell.HNG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 42 69 6e 61 72 79 52 65 61 64 00 } //01 00  䈀湩牡剹慥d
		$a_01_1 = {5f 61 73 70 78 00 5f 5f 63 74 72 6c 00 5f 5f 77 00 } //01 00 
		$a_01_2 = {12 15 03 20 00 02 04 20 00 12 19 05 20 01 01 12 } //01 00 
		$a_01_3 = {41 70 70 5f 57 65 62 5f } //00 00  App_Web_
	condition:
		any of ($a_*)
 
}