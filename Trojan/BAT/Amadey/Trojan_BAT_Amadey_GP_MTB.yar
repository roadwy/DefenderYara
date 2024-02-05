
rule Trojan_BAT_Amadey_GP_MTB{
	meta:
		description = "Trojan:BAT/Amadey.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 02 11 08 02 11 08 91 11 01 61 11 00 11 03 91 61 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}