
rule Trojan_BAT_Injector_AKQ_MTB{
	meta:
		description = "Trojan:BAT/Injector.AKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 28 2c 00 00 0a 13 08 11 06 28 2c 00 00 0a 13 09 11 07 11 08 11 09 28 12 00 00 06 13 0a 11 0a 28 2c 00 00 0a 13 0b 11 04 39 0f 00 00 00 72 65 02 00 70 80 01 00 00 04 38 0a 00 00 00 72 a5 02 00 70 80 01 00 00 04 73 01 00 00 06 13 0c 11 0c 7e 01 00 00 04 11 0b 6f 11 00 00 06 2a } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}