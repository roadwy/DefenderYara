
rule Trojan_BAT_Lazy_MKA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.MKA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 16 07 16 1f 10 28 65 00 00 0a 08 16 07 1f 0f 1f 10 28 65 00 00 0a 06 07 6f 9b 00 00 0a 06 18 6f 9c 00 00 0a 06 6f 9d 00 00 0a 0d 09 04 16 04 8e 69 6f 9e 00 00 0a 13 04 de 46 73 62 00 00 0a 2b a2 0a 2b a1 0b 2b a9 73 9f 00 00 0a 2b a4 28 a0 00 00 0a 2b 9f 02 2b 9e 6f a1 00 00 0a 38 96 ff ff ff 28 a2 00 00 0a 38 8e ff ff ff 0c 38 8d ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}