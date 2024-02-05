
rule Trojan_BAT_AgentTesla_MBAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {34 44 2d 35 41 2d 39 30 4f 2d 30 33 4f 4f 4f 2d 30 34 4f 4f 4f 2d 46 46 2d 46 46 4f 4f 2d 42 38 4f 4f 4f 4f 4f 4f } //05 00 
		$a_01_1 = {30 45 2d 31 46 2d 42 41 2d 30 45 4f 2d 42 34 2d 30 39 2d 43 44 2d 32 31 2d 42 38 2d 30 31 2d 34 43 2d 43 44 2d 32 } //01 00 
		$a_01_2 = {54 6f 53 42 79 74 65 } //01 00 
		$a_01_3 = {53 70 6c 69 74 } //01 00 
		$a_01_4 = {52 65 70 6c 61 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}