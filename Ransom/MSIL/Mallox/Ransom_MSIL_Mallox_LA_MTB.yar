
rule Ransom_MSIL_Mallox_LA_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.LA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 0c 17 58 93 11 05 61 13 06 1a 13 0e 38 0e 90 01 03 11 0c 19 58 13 0c 11 06 1f 1f 5f 11 06 20 c0 90 01 03 5f 17 63 60 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}