
rule Trojan_BAT_zgRAT_V_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 00 06 d0 36 00 00 02 28 90 01 01 01 00 06 6f 90 01 01 00 00 0a 73 90 01 01 00 00 0a 80 61 00 00 04 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}