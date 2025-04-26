
rule Trojan_BAT_Injector_TNAP_MTB{
	meta:
		description = "Trojan:BAT/Injector.TNAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 73 27 00 00 0a 0a 06 16 73 28 00 00 0a 0b 73 29 00 00 0a 0c 20 00 04 00 00 8d 32 00 00 01 0d 2b 2a 00 07 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 11 04 16 fe 02 16 fe 01 13 05 11 05 2c 02 2b 11 08 09 16 11 04 6f ?? ?? ?? 0a 00 00 17 13 06 2b d1 07 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 13 07 2b 00 11 07 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}