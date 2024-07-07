
rule Trojan_BAT_Bladabindi_PTJN_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PTJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {b7 16 6f 33 00 00 0a 13 0b 06 08 16 11 0b 6f 15 00 00 0a 06 6f 18 00 00 0a 07 33 22 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}