
rule Trojan_BAT_Lazy_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {04 17 9a 28 90 01 01 00 00 0a 7e 90 01 02 00 04 18 9a 28 90 01 01 00 00 0a 6f 90 01 02 00 0a 13 01 38 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}