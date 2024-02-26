
rule Trojan_BAT_Tedy_SPQN_MTB{
	meta:
		description = "Trojan:BAT/Tedy.SPQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {0d 1c 2c d2 09 06 6f 90 01 03 0a 16 2d ab 00 06 6f 90 01 03 0a 13 04 11 04 13 07 16 2d 9b de 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}