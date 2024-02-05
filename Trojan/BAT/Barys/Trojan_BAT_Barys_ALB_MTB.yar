
rule Trojan_BAT_Barys_ALB_MTB{
	meta:
		description = "Trojan:BAT/Barys.ALB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 06 8e b7 17 da 13 0a 13 08 2b 13 06 11 08 06 11 08 91 08 11 08 91 61 9c 11 08 17 d6 13 08 11 08 11 0a 31 e7 } //00 00 
	condition:
		any of ($a_*)
 
}