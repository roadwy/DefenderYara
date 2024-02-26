
rule Trojan_BAT_Rozena_EEAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.EEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 08 06 08 91 1b 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 08 06 8e 69 3f } //00 00 
	condition:
		any of ($a_*)
 
}