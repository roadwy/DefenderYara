
rule Trojan_BAT_AgentTesla_NVA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 32 39 31 35 34 39 62 35 2d 64 30 39 62 2d 34 32 35 62 2d 38 65 35 32 2d 34 31 38 37 66 33 33 66 36 64 30 32 } //01 00 
		$a_01_1 = {50 00 6c 00 61 00 6e 00 74 00 73 00 5f 00 76 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f } //01 00 
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00 
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}