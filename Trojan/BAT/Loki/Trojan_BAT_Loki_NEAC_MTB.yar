
rule Trojan_BAT_Loki_NEAC_MTB{
	meta:
		description = "Trojan:BAT/Loki.NEAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {d0 18 00 00 01 28 11 00 00 0a 02 75 1b 00 00 01 28 12 00 00 0a 16 8d 10 00 00 01 6f 13 00 00 0a 26 2a } //05 00 
		$a_01_1 = {44 61 74 61 43 65 6e 74 65 72 5f 4f 6e 44 69 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}