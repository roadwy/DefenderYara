
rule Trojan_BAT_Chopper_MAAA_MTB{
	meta:
		description = "Trojan:BAT/Chopper.MAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 12 00 00 01 fe 0b 01 00 25 17 9a 74 13 00 00 01 fe 0b 02 00 25 18 9a 0a 26 02 6f 12 00 00 0a 28 18 00 00 0a 74 1a 00 00 01 7b 19 00 00 0a 25 16 03 a2 25 17 04 a2 25 18 06 a2 26 02 6f 12 00 00 0a 28 18 00 00 0a } //1
		$a_01_1 = {57 17 a2 03 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 27 00 00 00 05 00 00 00 04 00 00 00 17 00 00 00 04 00 00 00 04 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}