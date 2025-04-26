
rule Trojan_BAT_Heracles_MBFR_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 64 00 63 00 78 00 78 00 63 00 6b 00 6e 00 6e 00 00 0d 64 00 63 00 63 00 73 00 6e 00 78 00 00 11 64 00 63 00 63 00 73 00 78 00 73 00 63 00 79 00 00 13 64 00 63 00 63 00 73 00 63 00 77 00 73 00 63 00 62 } //1
		$a_01_1 = {62 78 62 64 63 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 bxbdc.Properties.Resources.resource
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}