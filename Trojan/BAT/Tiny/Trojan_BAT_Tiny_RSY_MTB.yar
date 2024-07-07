
rule Trojan_BAT_Tiny_RSY_MTB{
	meta:
		description = "Trojan:BAT/Tiny.RSY!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 0e 00 00 06 28 01 00 00 2b 28 02 00 00 2b 0a de 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}