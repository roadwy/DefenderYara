
rule Trojan_BAT_ClipBanker_ATD_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ATD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 09 00 00 28 07 00 00 0a fe 0e 00 00 7e 08 00 00 0a fe 0e 01 00 fe 0c 00 00 39 8b 00 00 00 fe 0c 00 00 8e 39 81 00 00 00 fe 0c } //00 00 
	condition:
		any of ($a_*)
 
}