
rule Trojan_BAT_LokiBot_SPAD_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.SPAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 9a 13 06 00 11 06 6f ?? ?? ?? 0a 16 fe 01 13 08 11 08 2c 02 2b 34 11 06 72 a9 45 00 70 1f 0c 17 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 09 11 09 2c 02 2b 18 11 06 28 ?? ?? ?? 0a d2 13 07 7e 01 00 00 04 11 07 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 11 04 8e 69 32 a4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}