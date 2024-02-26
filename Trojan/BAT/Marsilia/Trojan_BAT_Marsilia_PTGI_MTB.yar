
rule Trojan_BAT_Marsilia_PTGI_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {7e 01 00 00 04 72 71 00 00 70 73 12 00 00 0a 28 90 01 01 00 00 0a 72 c5 00 00 70 28 90 01 01 00 00 0a 6f 15 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}