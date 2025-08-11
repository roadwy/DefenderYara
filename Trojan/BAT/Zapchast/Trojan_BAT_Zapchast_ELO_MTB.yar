
rule Trojan_BAT_Zapchast_ELO_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.ELO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 11 10 58 11 13 11 13 8e 69 12 01 6f 20 00 00 06 2d 06 73 0b 00 00 0a 7a 11 0d 1f 28 58 13 0d 11 0f 17 58 13 0f 11 0f 11 0e 32 84 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}