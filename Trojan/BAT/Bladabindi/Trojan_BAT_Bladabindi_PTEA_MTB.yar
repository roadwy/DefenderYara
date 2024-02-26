
rule Trojan_BAT_Bladabindi_PTEA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.PTEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 62 03 00 70 28 90 01 01 00 00 0a 26 02 28 90 01 01 01 00 0a 0a 28 90 01 01 01 00 0a 06 16 06 8e 69 6f 68 01 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}