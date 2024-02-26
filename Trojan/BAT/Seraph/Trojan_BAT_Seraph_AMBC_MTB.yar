
rule Trojan_BAT_Seraph_AMBC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 06 11 07 11 05 11 07 28 90 01 02 00 06 20 90 01 02 00 00 61 d1 9d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}