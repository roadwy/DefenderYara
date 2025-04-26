
rule Trojan_BAT_Marsilia_SNI_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.SNI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0b 07 6f 11 00 00 0a 72 fe 5e 00 70 7e 03 00 00 04 28 05 00 00 06 6f 12 00 00 0a 26 07 6f 11 00 00 0a 72 20 5f 00 70 7e 03 00 00 04 28 05 00 00 06 6f 12 00 00 0a 26 07 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}