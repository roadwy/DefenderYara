
rule Trojan_BAT_RedLine_DS_MTB{
	meta:
		description = "Trojan:BAT/RedLine.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 2a 00 00 0a 2c 08 7e 0a 00 00 0a 0a de 19 02 28 37 00 00 06 03 28 36 00 00 06 28 37 00 00 06 0a de 05 26 02 0a de 00 06 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}