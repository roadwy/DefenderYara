
rule Trojan_BAT_Mamut_RPQ_MTB{
	meta:
		description = "Trojan:BAT/Mamut.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {16 2d cc 11 04 11 05 09 11 05 09 8e 69 5d 91 07 11 05 91 61 d2 9c 11 05 17 58 13 05 11 05 07 8e 69 16 2d fc 32 da 11 04 13 06 1b 2c d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}