
rule Trojan_BAT_AgentTesla_CAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_81_0 = {00 50 72 6f 54 00 4b 69 63 6b 00 } //01 00 
		$a_81_1 = {00 43 5f 44 00 70 32 00 48 75 6e 74 65 72 00 53 } //01 00  䌀䑟瀀2畈瑮牥匀
		$a_81_2 = {00 52 65 74 75 72 6e 45 72 72 6f 72 00 4d 65 73 73 61 67 65 00 } //01 00 
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_81_5 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_81_6 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_81_7 = {54 6f 43 68 61 72 41 72 72 61 79 } //01 00  ToCharArray
		$a_81_8 = {47 65 74 54 79 70 65 73 } //01 00  GetTypes
		$a_81_9 = {50 61 72 61 6d 41 72 72 61 79 30 } //01 00  ParamArray0
		$a_81_10 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //00 00  ArrayAttribute
	condition:
		any of ($a_*)
 
}