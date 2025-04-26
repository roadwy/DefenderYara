
rule Trojan_BAT_AveMaria_NEAX_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NEAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 7e 01 00 00 04 02 7e 01 00 00 04 02 91 20 29 02 00 00 59 d2 9c 2a } //5
		$a_01_1 = {63 00 59 00 30 00 64 00 69 00 51 00 45 00 6d 00 } //3 cY0diQEm
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}