
rule Trojan_BAT_Injector_SXA_MTB{
	meta:
		description = "Trojan:BAT/Injector.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {12 01 7b 19 00 00 04 11 07 08 09 12 08 28 ?? 00 00 06 2d 2a 12 01 7b 19 00 00 04 17 28 ?? 00 00 06 26 } //30
		$a_03_1 = {13 04 11 04 16 72 ?? ?? 00 70 a2 11 04 17 6f ?? 00 00 0a 0a 06 8e 69 73 ?? 00 00 0a 0b 06 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}