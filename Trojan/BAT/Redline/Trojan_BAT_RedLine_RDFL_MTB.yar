
rule Trojan_BAT_RedLine_RDFL_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 12 02 28 43 00 00 0a 9c 25 17 12 02 28 44 00 00 0a 9c 25 18 12 02 28 45 00 00 0a 9c 6f 46 00 00 0a 00 00 11 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}