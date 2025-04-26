
rule Trojan_BAT_Vidar_SWA_MTB{
	meta:
		description = "Trojan:BAT/Vidar.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 28 15 00 00 0a 6f 16 00 00 0a 6f 17 00 00 0a 0a 06 73 18 00 00 0a 25 17 6f 19 00 00 0a 00 25 72 01 00 00 70 6f 1a 00 00 0a 00 0b 00 07 28 1b 00 00 0a 26 00 de 05 26 00 00 de 00 16 28 1c 00 00 0a 00 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}