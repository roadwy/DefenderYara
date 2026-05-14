
rule Trojan_BAT_Heracles_SLWU_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLWU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 04 02 28 69 00 00 0a 0b 1d 13 09 38 bc fe ff ff 11 04 75 9d 00 00 01 07 74 03 00 00 1b 16 07 75 03 00 00 1b 8e b7 6f 1a 01 00 0a 28 a1 01 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}