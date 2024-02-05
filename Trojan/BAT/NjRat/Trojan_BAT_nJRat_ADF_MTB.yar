
rule Trojan_BAT_nJRat_ADF_MTB{
	meta:
		description = "Trojan:BAT/nJRat.ADF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {13 04 00 07 08 16 20 00 10 00 00 6f ef 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0d 11 04 08 16 11 05 6f 54 00 00 0a 00 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb } //00 00 
	condition:
		any of ($a_*)
 
}