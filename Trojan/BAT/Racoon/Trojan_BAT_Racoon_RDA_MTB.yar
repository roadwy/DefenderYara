
rule Trojan_BAT_Racoon_RDA_MTB{
	meta:
		description = "Trojan:BAT/Racoon.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 19 00 00 0a 02 16 03 8e 69 6f 1a 00 00 0a 0a 06 0b } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}