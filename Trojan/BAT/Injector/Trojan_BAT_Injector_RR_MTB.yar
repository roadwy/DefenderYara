
rule Trojan_BAT_Injector_RR_MTB{
	meta:
		description = "Trojan:BAT/Injector.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 2b 00 00 0a 2c 07 07 0a 17 2b d9 de 3e 07 28 37 00 00 0a 28 49 00 00 0a 6f 2c 00 00 0a de 0e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Injector_RR_MTB_2{
	meta:
		description = "Trojan:BAT/Injector.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1d 8d 52 00 00 01 13 1f 7e e3 00 00 04 02 11 1e 11 1f 16 11 1d 28 [0-05] 00 11 10 11 0a 7b 18 00 00 04 7e e1 00 00 04 7e e4 00 00 04 11 0f 28 [0-05] 11 1c 6a 58 28 [0-05] 11 1f 11 1d 12 19 6f 42 00 00 06 26 00 11 1a 17 58 68 13 1a 11 1a 11 04 fe 04 13 21 11 21 3a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}