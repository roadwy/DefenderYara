
rule Trojan_BAT_Lokibot_SST2_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.SST2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00 
		$a_81_1 = {5a 75 6c 61 5f 48 41 43 4b 2e 65 78 65 } //01 00 
		$a_81_2 = {52 75 6e 50 45 2e 64 6c 6c } //01 00 
		$a_81_3 = {52 75 6e 50 45 2d 4d 65 74 68 6f 64 2d 42 79 70 61 73 73 2d 41 4d 53 49 2d 6d 61 69 6e } //01 00 
		$a_81_4 = {57 65 62 43 6c 69 65 6e 74 } //01 00 
		$a_81_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //00 00 
	condition:
		any of ($a_*)
 
}