
rule Trojan_BAT_Vidar_PSZF_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PSZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 d7 00 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 06 18 16 8d 57 00 00 01 6f 71 04 00 06 20 f1 08 00 00 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}