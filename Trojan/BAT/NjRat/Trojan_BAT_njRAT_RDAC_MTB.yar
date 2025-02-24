
rule Trojan_BAT_njRAT_RDAC_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 80 02 01 00 04 28 0d 00 00 2b fe 0c 00 00 fe 06 fa 00 00 06 73 d0 00 00 0a 28 0e 00 00 2b 28 0f 00 00 2b fe 0e 02 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}