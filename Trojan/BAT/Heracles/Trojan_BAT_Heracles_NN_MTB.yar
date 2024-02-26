
rule Trojan_BAT_Heracles_NN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {0b 08 17 58 0c 08 06 8e 69 17 59 fe 02 16 fe 01 13 06 11 06 2d dc } //00 00 
	condition:
		any of ($a_*)
 
}