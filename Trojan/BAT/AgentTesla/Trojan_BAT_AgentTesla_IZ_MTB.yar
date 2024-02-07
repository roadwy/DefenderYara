
rule Trojan_BAT_AgentTesla_IZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 0c 11 12 11 0a 11 12 94 11 0b 11 12 94 58 9e 11 0d 11 0c 11 12 94 6c 90 01 09 5b 58 13 0d 11 12 17 58 13 12 11 12 1b 32 d0 90 00 } //01 00 
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_3 = {47 65 74 4d 65 6d 62 65 72 } //01 00  GetMember
		$a_81_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //00 00  RijndaelManaged
	condition:
		any of ($a_*)
 
}