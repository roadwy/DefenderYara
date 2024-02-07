
rule Trojan_BAT_AgentTesla_JLB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 01 02 11 04 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 84 28 90 01 03 0a 28 90 01 03 06 26 38 90 01 03 00 11 04 11 02 3e 90 01 03 ff 38 90 01 03 00 11 04 18 d6 13 04 38 90 01 03 ff 11 01 6f 90 01 03 0a 13 00 38 90 01 03 ff 00 02 6f 90 00 } //01 00 
		$a_03_1 = {11 02 11 02 d8 1a d8 13 03 38 90 01 03 00 00 16 13 0d 38 90 00 } //01 00 
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00  GetMethods
		$a_81_3 = {42 69 67 45 6e 64 69 61 6e 55 6e 69 63 6f 64 65 } //00 00  BigEndianUnicode
	condition:
		any of ($a_*)
 
}