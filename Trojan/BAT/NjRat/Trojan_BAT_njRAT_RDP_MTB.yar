
rule Trojan_BAT_njRAT_RDP_MTB{
	meta:
		description = "Trojan:BAT/njRAT.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0e 06 4a 11 0d 06 4a 91 11 0c 06 4a 11 0c 8e 69 5d 91 61 d2 9c 00 06 06 4a 17 58 54 } //00 00 
	condition:
		any of ($a_*)
 
}