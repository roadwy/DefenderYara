
rule Trojan_BAT_Heracles_SGDA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SGDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f 14 00 00 0a 06 6f 15 00 00 0a 6f 16 00 00 0a 0b 73 17 00 00 0a 0c 20 ?? ?? ?? 00 8d 15 00 00 01 25 d0 04 00 00 04 28 18 00 00 0a 73 19 00 00 0a 0d 09 07 16 73 1a 00 00 0a 13 04 1f 10 8d 15 00 00 01 13 05 38 0b 00 00 00 08 11 05 16 11 06 6f 1b 00 00 0a 11 04 11 05 16 11 05 8e 69 6f 1c 00 00 0a 25 13 06 16 3d de ff ff ff } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}