
rule Trojan_BAT_Rozena_SPPX_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 07 91 08 61 d2 9c 11 07 17 58 13 07 } //00 00 
	condition:
		any of ($a_*)
 
}