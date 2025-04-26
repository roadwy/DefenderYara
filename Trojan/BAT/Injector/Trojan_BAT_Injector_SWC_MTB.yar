
rule Trojan_BAT_Injector_SWC_MTB{
	meta:
		description = "Trojan:BAT/Injector.SWC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {02 7b 04 00 00 04 03 02 7b 04 00 00 04 03 91 20 45 01 00 00 61 d2 9c 2a } //2
		$a_03_1 = {02 7e 14 00 00 0a 7d 01 00 00 04 02 28 ?? 00 00 0a 20 fc 05 00 00 28 ?? 00 00 0a 02 28 ?? 00 00 06 20 3c 15 00 00 28 ?? 00 00 0a 02 7b 03 00 00 04 72 01 00 00 70 6f ?? 00 00 0a 14 16 8d 1b 00 00 01 6f ?? 00 00 0a 26 2a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}