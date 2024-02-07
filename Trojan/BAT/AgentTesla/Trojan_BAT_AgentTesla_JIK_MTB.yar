
rule Trojan_BAT_AgentTesla_JIK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 06 20 00 01 00 00 6f 90 01 03 0a 06 20 80 00 00 00 6f 90 01 03 0a 28 90 01 03 0a 03 6f 90 01 03 0a 72 90 01 03 70 03 16 73 90 01 03 06 6f 90 01 03 06 7e 90 01 03 04 25 2d 17 26 7e 90 00 } //0a 00 
		$a_03_1 = {20 00 01 00 00 6f 90 01 03 0a 11 0a 20 80 00 00 00 6f 90 01 03 0a 28 90 01 03 0a 25 26 03 6f 90 01 03 0a 25 26 72 90 01 03 70 03 16 73 90 01 03 06 6f 90 01 03 06 25 26 7e 90 01 03 04 25 2d 21 90 00 } //01 00 
		$a_81_2 = {61 61 73 64 61 73 64 61 73 64 64 61 73 73 6a 64 73 75 64 61 62 73 68 61 64 61 64 } //01 00  aasdasdasddassjdsudabshadad
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}