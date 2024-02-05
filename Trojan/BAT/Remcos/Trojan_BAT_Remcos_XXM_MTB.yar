
rule Trojan_BAT_Remcos_XXM_MTB{
	meta:
		description = "Trojan:BAT/Remcos.XXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 09 08 09 08 8e 69 5d 91 07 09 91 61 d2 6f } //00 00 
	condition:
		any of ($a_*)
 
}