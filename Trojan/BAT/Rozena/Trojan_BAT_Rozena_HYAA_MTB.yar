
rule Trojan_BAT_Rozena_HYAA_MTB{
	meta:
		description = "Trojan:BAT/Rozena.HYAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 11 05 07 11 05 91 1f 41 61 20 ff 00 00 00 5f d2 9c 11 05 17 58 13 05 11 05 07 8e 69 32 d0 } //00 00 
	condition:
		any of ($a_*)
 
}