
rule Ransom_MSIL_Locky_SG_MTB{
	meta:
		description = "Ransom:MSIL/Locky.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 04 7e aa 00 00 04 11 04 7e 70 00 00 04 11 04 28 23 01 00 06 28 13 02 00 06 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}