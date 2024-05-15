
rule Trojan_BAT_Marsilia_AMS_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0a 0b 00 1f 0d 02 07 6f 11 00 00 0a 28 05 00 00 06 16 28 02 00 00 06 0c de 16 07 2c 07 07 } //00 00 
	condition:
		any of ($a_*)
 
}