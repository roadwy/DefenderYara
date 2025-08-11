
rule Trojan_BAT_Heracles_SLCD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 6f 29 00 00 0a 25 26 0c 1f 61 6a 08 28 41 00 00 06 25 26 0d 09 28 2a 00 00 0a 25 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}