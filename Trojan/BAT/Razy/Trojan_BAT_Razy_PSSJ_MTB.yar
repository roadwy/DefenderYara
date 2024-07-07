
rule Trojan_BAT_Razy_PSSJ_MTB{
	meta:
		description = "Trojan:BAT/Razy.PSSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 07 17 99 28 90 01 01 00 00 06 58 6f 90 01 01 00 00 0a 00 09 28 90 01 01 00 00 2b 13 04 09 28 90 01 01 00 00 2b 08 fe 02 13 0b 11 0b 2c 1c 00 09 28 90 01 01 00 00 2b 13 06 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}