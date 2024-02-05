
rule Ransom_MSIL_Maoloa_UH_MTB{
	meta:
		description = "Ransom:MSIL/Maoloa.UH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 00 6f 15 00 00 0a 11 03 16 11 03 8e 69 6f 16 00 00 0a 13 04 38 0c 00 00 00 28 09 00 00 06 13 03 38 da ff ff ff } //00 00 
	condition:
		any of ($a_*)
 
}