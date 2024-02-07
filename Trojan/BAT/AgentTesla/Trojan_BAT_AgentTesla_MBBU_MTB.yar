
rule Trojan_BAT_AgentTesla_MBBU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 00 4b 00 2f 00 64 00 56 00 78 00 5a 00 7a 00 50 00 59 00 42 00 6a 00 42 00 52 00 6d 00 67 00 53 00 65 00 59 00 78 00 68 00 33 00 46 00 58 00 6e 00 75 00 35 00 38 00 4f 00 49 00 75 00 63 00 54 00 38 00 57 00 77 00 31 00 46 00 } //00 00  iK/dVxZzPYBjBRmgSeYxh3FXnu58OIucT8Ww1F
	condition:
		any of ($a_*)
 
}