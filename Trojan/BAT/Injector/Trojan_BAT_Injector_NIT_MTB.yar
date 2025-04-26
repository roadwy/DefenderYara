
rule Trojan_BAT_Injector_NIT_MTB{
	meta:
		description = "Trojan:BAT/Injector.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 72 1d 00 00 70 28 ?? 00 00 0a 72 31 00 00 70 72 45 00 00 70 28 ?? 00 00 06 00 02 28 ?? 00 00 0a 72 5b 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 00 28 ?? 00 00 0a 72 5b 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 28 ?? 00 00 0a 72 73 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 15 28 ?? 00 00 0a 00 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_Injector_NIT_MTB_2{
	meta:
		description = "Trojan:BAT/Injector.NIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 06 11 04 91 03 11 04 03 8e b7 5d 91 11 04 08 d6 03 8e b7 d6 1d 5f 62 d2 20 00 01 00 00 5d 61 b4 9c 11 04 17 d6 13 04 11 04 11 05 31 d0 } //2
		$a_03_1 = {02 08 11 04 6f ?? 00 00 0a 0d 09 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 17 d6 13 04 11 04 11 06 31 b2 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}