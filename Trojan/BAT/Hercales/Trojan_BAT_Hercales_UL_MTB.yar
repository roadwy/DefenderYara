
rule Trojan_BAT_Hercales_UL_MTB{
	meta:
		description = "Trojan:BAT/Hercales.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 07 02 58 20 06 78 ab 6c 11 00 59 11 01 61 61 11 0a 11 00 20 bb 22 1d 6a 61 11 01 59 5f 61 13 41 } //00 00 
	condition:
		any of ($a_*)
 
}