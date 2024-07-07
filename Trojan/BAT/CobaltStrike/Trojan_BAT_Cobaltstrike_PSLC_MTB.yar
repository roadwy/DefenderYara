
rule Trojan_BAT_Cobaltstrike_PSLC_MTB{
	meta:
		description = "Trojan:BAT/Cobaltstrike.PSLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 33 00 00 70 28 90 01 03 0a 0b 00 28 08 00 00 06 0c 06 18 73 90 01 03 0a 13 05 00 11 05 08 16 08 8e 69 6f 90 01 03 0a 00 00 de 0d 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}