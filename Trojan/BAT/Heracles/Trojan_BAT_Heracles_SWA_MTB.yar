
rule Trojan_BAT_Heracles_SWA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 a3 25 00 00 01 0c 08 6f 41 01 00 0a 72 48 1a 00 70 28 b5 00 00 0a 2c 14 08 72 94 1a 00 70 20 00 01 00 00 14 14 14 6f 42 01 00 0a 26 07 17 58 0b 07 06 8e 69 32 c8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}