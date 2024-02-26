
rule Trojan_BAT_njRAT_RDX_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4 } //00 00 
	condition:
		any of ($a_*)
 
}