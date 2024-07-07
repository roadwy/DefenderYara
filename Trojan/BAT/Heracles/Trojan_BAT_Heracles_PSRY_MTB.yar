
rule Trojan_BAT_Heracles_PSRY_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 16 00 00 0a 00 11 07 72 9d 01 00 70 28 17 00 00 0a 16 fe 01 13 10 11 10 2d 0c 00 11 06 28 18 00 00 0a 26 00 2b 0f 00 11 06 28 19 00 00 0a 28 18 00 00 0a 26 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}