
rule Trojan_BAT_AgentTesla_ABDS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {11 05 11 0a 74 90 01 03 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 90 01 03 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f 90 01 03 0a 26 1f 0c 13 0e 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_2 = {38 36 61 31 34 61 64 33 62 37 63 62 34 34 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  86a14ad3b7cb44.Resources.resources
	condition:
		any of ($a_*)
 
}