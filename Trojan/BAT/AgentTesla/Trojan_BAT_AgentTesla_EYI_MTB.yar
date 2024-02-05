
rule Trojan_BAT_AgentTesla_EYI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EYI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 4f 6f 30 48 6f 35 71 48 43 56 64 4a 68 63 6a 49 6a 77 71 4e 7a 4e 59 63 69 41 71 4a 69 4e 62 49 52 63 78 4e 58 4d 2f 4d 44 77 56 4f 79 31 72 } //01 00 
		$a_01_1 = {55 77 46 56 63 76 35 39 4f 7a 48 70 56 57 55 4b 54 68 45 79 70 42 57 4a 78 47 6a 56 69 67 48 69 6c 74 34 55 45 47 4c 5a 2b 35 66 59 76 79 6e 39 } //00 00 
	condition:
		any of ($a_*)
 
}