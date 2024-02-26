
rule Ransom_MSIL_Mallox_LL_MTB{
	meta:
		description = "Ransom:MSIL/Mallox.LL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 1b 11 09 11 23 11 21 61 19 11 1a 58 61 11 2e 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}