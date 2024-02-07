
rule Trojan_BAT_AgentTesla_CAI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 16 13 06 2b 1b 09 11 06 08 11 06 9a 1f 10 28 90 01 01 00 00 0a d2 6f 90 01 01 00 00 0a 00 11 06 17 58 13 06 11 06 08 8e 69 fe 04 13 07 11 07 2d d8 90 00 } //01 00 
		$a_01_1 = {53 70 6c 69 74 } //01 00  Split
		$a_01_2 = {54 6f 53 42 79 74 65 } //00 00  ToSByte
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CAI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a d9 8a } //0a 00 
		$a_00_1 = {db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 db 95 } //0a 00 
		$a_00_2 = {d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 d8 b5 } //0a 00 
		$a_00_3 = {d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 d8 b4 } //01 00 
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_5 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //01 00  GetResourceString
		$a_81_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}