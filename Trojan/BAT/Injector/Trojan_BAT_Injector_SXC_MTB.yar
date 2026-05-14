
rule Trojan_BAT_Injector_SXC_MTB{
	meta:
		description = "Trojan:BAT/Injector.SXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 28 13 00 00 06 0a 18 8d 07 00 00 01 13 04 11 04 16 72 ?? ?? 00 70 a2 11 04 17 72 ?? ?? 00 70 a2 11 04 0b 07 } //30
		$a_01_1 = {28 15 00 00 06 12 01 7b 13 00 00 04 08 03 03 8e 69 12 03 28 06 00 00 06 2d 2a } //20
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}