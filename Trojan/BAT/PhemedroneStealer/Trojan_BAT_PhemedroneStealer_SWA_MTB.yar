
rule Trojan_BAT_PhemedroneStealer_SWA_MTB{
	meta:
		description = "Trojan:BAT/PhemedroneStealer.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 02 00 00 2b 7e 29 00 00 04 25 2d 17 26 7e 28 00 00 04 fe 06 5e 00 00 06 73 6c 00 00 0a 25 80 29 00 00 04 28 03 00 00 2b 7e 2a 00 00 04 25 2d 17 26 7e 28 00 00 04 fe 06 5f 00 00 06 73 6e 00 00 0a 25 80 2a 00 00 04 28 04 00 00 2b 28 05 00 00 2b 08 fe 06 64 00 00 06 73 71 00 00 0a 6f 72 00 00 0a 28 66 00 00 06 08 7b 2e 00 00 04 28 75 00 00 06 de 14 08 7b 2e 00 00 04 2c 0b 08 7b 2e 00 00 04 6f 01 00 00 0a dc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}