
rule Trojan_BAT_Venomrat_MCT_MTB{
	meta:
		description = "Trojan:BAT/Venomrat.MCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {47 6f 68 78 77 61 6b 66 6d 62 68 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Gohxwakfmbh.Properties
		$a_01_1 = {73 65 72 61 61 61 33 36 39 } //1 seraaa369
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}