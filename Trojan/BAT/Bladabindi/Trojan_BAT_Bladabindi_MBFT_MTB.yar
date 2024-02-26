
rule Trojan_BAT_Bladabindi_MBFT_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {67 69 c2 84 64 54 54 60 54 54 54 54 58 54 54 54 54 42 42 4b 54 54 5f 7a 54 54 54 54 54 54 54 54 54 64 54 54 54 54 54 54 } //00 00 
	condition:
		any of ($a_*)
 
}