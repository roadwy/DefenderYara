
rule Trojan_BAT_Bladabindi_SWA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 16 11 04 11 07 11 06 28 1f 00 00 0a 11 07 11 06 58 13 07 07 11 05 16 20 00 01 00 00 6f 20 00 00 0a 25 13 06 16 30 d7 20 61 ff 6f 00 13 08 06 13 0d 16 13 0e 2b 1a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}