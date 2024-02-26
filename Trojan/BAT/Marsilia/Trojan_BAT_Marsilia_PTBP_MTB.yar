
rule Trojan_BAT_Marsilia_PTBP_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2c 42 02 7b 10 00 00 04 72 d9 01 00 70 6f 24 00 00 0a 6f 25 00 00 0a 0c 12 02 28 90 01 01 00 00 0a 2d 3f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}