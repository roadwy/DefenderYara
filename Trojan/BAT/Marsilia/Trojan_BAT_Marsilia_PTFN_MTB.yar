
rule Trojan_BAT_Marsilia_PTFN_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 7d 00 00 70 72 57 00 00 70 6f 17 00 00 0a 00 72 57 00 00 70 28 90 01 01 00 00 0a 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}