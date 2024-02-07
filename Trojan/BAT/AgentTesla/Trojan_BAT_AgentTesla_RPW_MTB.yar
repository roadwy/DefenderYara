
rule Trojan_BAT_AgentTesla_RPW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {35 00 32 00 2e 00 37 00 38 00 2e 00 31 00 36 00 35 00 2e 00 31 00 36 00 35 00 } //01 00  52.78.165.165
		$a_01_1 = {52 00 46 00 30 00 32 00 31 00 33 00 36 00 30 00 30 00 30 00 30 00 33 00 31 00 2e 00 70 00 6e 00 67 00 } //01 00  RF02136000031.png
		$a_01_2 = {47 00 6f 00 61 00 61 00 64 00 66 00 64 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Goaadfd.Properties.Resources
		$a_01_3 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 20 00 53 00 63 00 61 00 6e 00 6e 00 65 00 72 00 } //00 00  Malware Scanner
	condition:
		any of ($a_*)
 
}