
rule Trojan_BAT_Injuke_GZAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.GZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 09 08 6f 90 01 01 00 00 0a 09 09 6f 90 01 01 00 00 0a 09 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 05 90 00 } //02 00 
		$a_03_1 = {11 08 02 74 90 01 01 00 00 1b 16 02 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}