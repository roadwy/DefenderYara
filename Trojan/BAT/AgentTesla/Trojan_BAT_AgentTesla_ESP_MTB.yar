
rule Trojan_BAT_AgentTesla_ESP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {59 43 7a 68 4c 57 45 74 34 6d 35 75 72 75 57 76 62 2b 2f 77 63 47 4f 77 36 48 46 6f 63 65 70 79 61 62 4c 6d 4d 32 38 7a 37 48 52 74 74 4f 78 31 } //01 00 
		$a_01_1 = {5a 76 37 6b 50 32 34 2f 32 6b 42 62 67 4e 68 42 57 67 48 61 51 6c 6e 43 32 6b 4e 44 67 39 4b 45 58 4d 54 66 78 56 6b 46 32 45 5a 62 68 74 6c 48 } //01 00 
		$a_01_2 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //01 00 
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}