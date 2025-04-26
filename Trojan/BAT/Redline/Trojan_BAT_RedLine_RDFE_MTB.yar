
rule Trojan_BAT_RedLine_RDFE_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDFE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 02 6f 19 00 00 0a 8e 69 6f 1d 00 00 0a 28 01 00 00 2b 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}