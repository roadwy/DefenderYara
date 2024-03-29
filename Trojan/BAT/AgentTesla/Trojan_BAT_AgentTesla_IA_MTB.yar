
rule Trojan_BAT_AgentTesla_IA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {06 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 61 d1 6f 90 01 03 0a 26 07 17 58 0b 07 02 6f 90 01 03 0a 32 d5 90 00 } //01 00 
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_2 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_3 = {78 6f 72 65 64 53 74 72 69 6e 67 } //00 00  xoredString
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_IA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.IA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1c 00 1c 00 11 00 00 14 00 "
		
	strings :
		$a_81_0 = {6a 66 64 73 69 6f 66 73 64 61 6f 66 } //14 00  jfdsiofsdaof
		$a_81_1 = {6a 66 61 69 61 77 64 64 6b 66 6b } //14 00  jfaiawddkfk
		$a_81_2 = {68 6e 62 7a 64 66 69 6b 65 61 6f } //14 00  hnbzdfikeao
		$a_81_3 = {6a 66 73 65 69 65 6f 66 71 77 65 } //14 00  jfseieofqwe
		$a_81_4 = {6e 73 64 67 66 6a 65 66 75 6a 65 32 } //14 00  nsdgfjefuje2
		$a_81_5 = {6d 6b 6a 73 65 66 6f 33 64 66 } //14 00  mkjsefo3df
		$a_81_6 = {6a 67 73 64 69 66 73 61 6f 66 67 32 } //14 00  jgsdifsaofg2
		$a_81_7 = {6a 66 64 61 77 64 61 77 6f } //14 00  jfdawdawo
		$a_81_8 = {6e 73 64 66 75 6a 65 69 6f 66 32 31 } //01 00  nsdfujeiof21
		$a_81_9 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_81_10 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_11 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_13 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //01 00  ResolveSignature
		$a_81_14 = {4c 6f 61 64 4d 6f 64 75 6c 65 } //01 00  LoadModule
		$a_81_15 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_16 = {47 65 74 54 79 70 65 73 } //00 00  GetTypes
	condition:
		any of ($a_*)
 
}