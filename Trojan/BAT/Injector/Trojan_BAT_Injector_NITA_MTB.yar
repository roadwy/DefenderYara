
rule Trojan_BAT_Injector_NITA_MTB{
	meta:
		description = "Trojan:BAT/Injector.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 01 00 02 74 ?? 00 00 01 08 20 00 04 00 00 d6 17 da 17 d6 8d ?? 00 00 01 28 ?? ?? 00 0a 74 ?? 00 00 1b 10 00 07 02 08 20 00 04 00 00 6f ?? ?? 00 0a 0d 08 09 d6 0c 09 20 00 04 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}