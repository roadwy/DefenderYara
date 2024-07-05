
rule Ransom_MSIL_Blocker_SPZM_MTB{
	meta:
		description = "Ransom:MSIL/Blocker.SPZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {13 13 11 1d 11 09 91 13 20 11 1d 11 09 11 90 01 01 11 90 01 01 61 11 1b 19 58 61 11 31 61 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}