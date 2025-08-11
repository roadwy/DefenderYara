
rule Trojan_BAT_Vidar_SLDE_MTB{
	meta:
		description = "Trojan:BAT/Vidar.SLDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {18 28 36 04 00 06 fe 0e 7a 02 fe 0c 7a 02 16 12 05 28 0a 00 00 0a 25 26 a2 fe 0c 7a 02 17 12 06 28 0c 00 00 0a 25 26 a2 fe 0c 7a 02 13 07 72 5b 00 00 70 11 07 28 0b 00 00 0a 25 26 26 72 9e 21 04 70 13 08 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}