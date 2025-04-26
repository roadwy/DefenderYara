
rule Trojan_BAT_Zilla_SWA_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 2f 00 00 06 28 2e 00 00 06 2c 03 26 2b 58 26 17 28 2e 00 00 06 2d 03 26 2b 4c 45 06 00 00 00 2f 00 00 00 08 00 00 00 08 00 00 00 2f 00 00 00 02 00 00 00 37 00 00 00 2b 06 02 28 29 00 00 06 28 03 00 00 06 28 2a 00 00 06 28 2b 00 00 06 28 2c 00 00 06 14 14 28 2d 00 00 06 26 1b 28 2e 00 00 06 2d b7 26 2b d3 02 28 1e 00 00 0a 2b cb 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}