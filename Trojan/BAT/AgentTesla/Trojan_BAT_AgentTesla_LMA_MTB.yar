
rule Trojan_BAT_AgentTesla_LMA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 20 80 00 00 00 6f 90 01 04 1e 8d 90 01 03 01 25 d0 90 01 03 04 28 90 01 03 0a 13 06 11 05 11 06 20 e8 03 00 00 73 90 01 03 0a 0c 06 08 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 04 06 08 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 06 17 6f 90 01 03 0a 73 90 01 03 0a 0d 09 06 6f 90 00 } //01 00 
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //00 00  GetTypeFromHandle
	condition:
		any of ($a_*)
 
}