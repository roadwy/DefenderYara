
rule Trojan_BAT_AgentTesla_ABCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //01 00  TransformFinalBlock
		$a_01_1 = {70 62 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //01 00  pbDebuggerPresent
		$a_01_2 = {24 34 33 66 34 38 62 61 38 2d 61 35 65 37 2d 34 38 32 66 2d 61 65 64 65 2d 37 35 33 31 65 30 37 64 62 30 31 31 } //03 00  $43f48ba8-a5e7-482f-aede-7531e07db011
		$a_01_3 = {56 00 6b 00 4a 00 59 00 51 00 30 00 4a 00 44 00 57 00 46 00 5a 00 49 00 52 00 31 00 4d 00 6b 00 } //03 00  VkJYQ0JDWFZIR1Mk
		$a_01_4 = {56 00 42 00 58 00 43 00 42 00 43 00 58 00 56 00 48 00 47 00 53 00 24 00 } //00 00  VBXCBCXVHGS$
	condition:
		any of ($a_*)
 
}