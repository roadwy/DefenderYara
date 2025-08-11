
rule Trojan_BAT_Bladabindi_SLAW_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.SLAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 02 2b 27 72 dd 00 00 70 2b 27 80 17 00 00 04 7e 17 00 00 04 14 2b 21 2c 0c 7e 17 00 00 04 2b 1f 80 18 00 00 04 de 2f 07 2b d5 28 d8 00 00 0a 2b d2 28 d9 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}