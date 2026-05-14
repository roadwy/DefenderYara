
rule Trojan_BAT_Jalapeno_MCT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.MCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {61 33 63 36 2d 37 62 34 30 32 66 38 38 37 39 34 62 } //1 a3c6-7b402f88794b
		$a_01_1 = {54 66 61 6d 69 77 78 68 6d 62 } //1 Tfamiwxhmb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}