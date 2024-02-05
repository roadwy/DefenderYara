
rule Trojan_BAT_Rozena_GP_MTB{
	meta:
		description = "Trojan:BAT/Rozena.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {08 09 02 09 02 09 91 03 09 07 5d 91 61 d2 25 13 04 9c 11 04 9c 09 17 58 0d 09 06 } //00 00 
	condition:
		any of ($a_*)
 
}