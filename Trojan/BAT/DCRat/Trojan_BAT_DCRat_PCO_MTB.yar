
rule Trojan_BAT_DCRat_PCO_MTB{
	meta:
		description = "Trojan:BAT/DCRat.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 40 02 00 0a 6f 41 02 00 0a 00 09 08 1f 10 6f 40 02 00 0a 6f 42 02 00 0a 00 09 09 6f 43 02 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}