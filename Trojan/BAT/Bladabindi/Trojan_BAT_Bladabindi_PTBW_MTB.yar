
rule Trojan_BAT_Bladabindi_PTBW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PTBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 06 00 00 0a 03 50 6f 04 00 00 0a 0a 06 28 90 01 01 00 00 0a 0b 07 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}