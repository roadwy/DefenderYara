
rule Trojan_BAT_AgentTesla_DRI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 90 01 03 0a b7 28 90 01 03 0a 28 90 01 03 0a 0b 07 0a 2b 00 90 00 } //01 00 
		$a_01_1 = {20 00 47 00 65 00 74 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 } //01 00   GetMethod 
		$a_01_2 = {20 00 49 00 6e 00 76 00 6f 00 6b 00 65 00 20 00 } //01 00   Invoke 
		$a_01_3 = {20 00 42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 20 00 } //00 00   Bunifu_TextBox 
	condition:
		any of ($a_*)
 
}