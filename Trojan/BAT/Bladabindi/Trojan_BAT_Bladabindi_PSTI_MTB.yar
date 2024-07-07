
rule Trojan_BAT_Bladabindi_PSTI_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PSTI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 09 28 b8 9b 3c 3c 14 16 9a 26 16 2d f9 28 3b 04 00 06 28 25 01 00 06 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}