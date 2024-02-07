
rule Trojan_BAT_AgentTesla_MBHP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 61 00 64 00 00 23 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 47 00 69 00 61 00 79 00 2e 00 43 00 43 00 4d } //05 00 
		$a_01_1 = {52 00 65 00 70 00 6c 00 61 00 63 00 65 00 } //05 00  Replace
		$a_01_2 = {53 00 74 00 72 00 69 00 6e 00 67 00 31 00 } //01 00  String1
		$a_01_3 = {54 6f 42 79 74 65 } //01 00  ToByte
		$a_01_4 = {53 70 6c 69 74 } //01 00  Split
		$a_01_5 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}