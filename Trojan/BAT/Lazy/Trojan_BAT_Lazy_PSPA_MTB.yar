
rule Trojan_BAT_Lazy_PSPA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PSPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 18 5b 02 08 18 6f 58 00 00 0a 1f 10 28 60 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0 } //00 00 
	condition:
		any of ($a_*)
 
}