
rule Trojan_BAT_Injector_ABK_MTB{
	meta:
		description = "Trojan:BAT/Injector.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0e 04 0b 07 17 2e 08 2b 00 07 18 2e 0b 2b 2f 00 02 03 5d 0c 08 0a 2b 2b 00 04 05 28 90 01 04 28 90 01 04 04 28 90 01 04 05 28 90 01 04 28 90 01 04 28 90 01 04 0a 2b 05 00 16 0a 2b 00 06 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}