
rule Trojan_BAT_AgentTesla_CDB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {06 11 04 28 90 01 03 0a 08 11 04 08 6f 90 01 03 0a 5d 17 d6 28 90 01 03 0a da 13 05 07 11 05 28 90 01 03 0a 28 90 01 03 06 28 90 01 03 0a 0b 11 04 17 d6 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CDB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 33 66 61 64 63 65 34 34 2d 39 30 33 37 2d 34 62 63 37 2d 39 32 64 30 2d 39 33 66 36 63 66 66 61 65 30 36 61 } //01 00  $3fadce44-9037-4bc7-92d0-93f6cffae06a
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //01 00  ArrayAttribute
		$a_81_3 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00  ParamArray0
		$a_81_4 = {49 45 78 70 61 6e 64 6f 2e 50 6c 75 67 } //01 00  IExpando.Plug
		$a_81_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_6 = {47 65 74 43 68 61 72 } //01 00  GetChar
		$a_81_7 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}