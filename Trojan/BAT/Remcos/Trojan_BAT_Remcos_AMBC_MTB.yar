
rule Trojan_BAT_Remcos_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 04 0e 08 04 8e 69 6f 90 01 01 00 00 0a 0a 06 0b 2b 00 07 2a 90 00 } //2
		$a_03_1 = {04 06 25 0b 6f 90 01 01 00 00 0a 00 07 0c 2b 00 08 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}