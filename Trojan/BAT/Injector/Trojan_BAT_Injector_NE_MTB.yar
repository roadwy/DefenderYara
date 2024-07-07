
rule Trojan_BAT_Injector_NE_MTB{
	meta:
		description = "Trojan:BAT/Injector.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 03 61 1f 10 59 06 7e 29 00 00 04 20 8a 00 00 00 7e 29 00 00 04 20 8a 00 00 00 91 7e 13 00 00 04 1f 5e 93 61 1f 3a 5f 9c 61 45 01 00 00 00 0d 00 00 00 } //1
		$a_01_1 = {91 7e 11 00 00 04 06 91 7e 16 00 00 04 1f 1f 5f 62 06 61 7e 17 00 00 04 58 61 d2 9c 1c 0c 2b 98 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}