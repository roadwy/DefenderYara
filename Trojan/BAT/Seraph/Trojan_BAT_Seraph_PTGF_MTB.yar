
rule Trojan_BAT_Seraph_PTGF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PTGF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {38 ea fa ff ff 11 01 28 90 01 01 00 00 06 11 07 28 90 01 01 00 00 06 28 90 01 01 00 00 06 6f 32 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}