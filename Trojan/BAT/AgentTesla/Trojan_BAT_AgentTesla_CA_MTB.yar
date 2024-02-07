
rule Trojan_BAT_AgentTesla_CA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {08 11 16 08 11 16 91 11 04 61 20 ff 00 00 00 5f d2 9c 11 16 17 58 13 16 11 16 08 8e 69 32 e1 } //01 00 
		$a_01_1 = {56 69 72 75 73 44 65 6c 65 74 65 64 } //01 00  VirusDeleted
		$a_01_2 = {4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 } //00 00  NtCreateThreadEx
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {2b 39 02 08 6f 90 01 04 28 90 01 04 13 04 11 04 28 90 01 04 28 90 01 04 da 13 05 07 11 05 28 90 01 04 28 90 01 04 28 90 01 04 0b 08 28 90 01 04 d6 0c 00 08 09 fe 04 13 06 11 06 2d bd 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 } //01 00  Decrypt
		$a_01_1 = {44 65 63 6f 6d 70 72 65 73 73 } //01 00  Decompress
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_3 = {4c 7a 6d 61 44 65 63 6f 64 65 72 } //01 00  LzmaDecoder
		$a_01_4 = {42 69 74 54 72 65 65 44 65 63 6f 64 65 72 } //01 00  BitTreeDecoder
		$a_01_5 = {52 65 76 65 72 73 65 44 65 63 6f 64 65 } //01 00  ReverseDecode
		$a_01_6 = {52 65 73 6f 6c 76 65 53 69 67 6e 61 74 75 72 65 } //0a 00  ResolveSignature
		$a_01_7 = {6a 66 64 61 77 64 61 77 6f 2e 65 78 65 } //0a 00  jfdawdawo.exe
		$a_81_8 = {68 6e 62 7a 64 66 69 6b 65 61 6f 2e 65 78 65 } //01 00  hnbzdfikeao.exe
		$a_01_9 = {44 65 62 75 67 67 65 72 } //01 00  Debugger
		$a_01_10 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_11 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_12 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //00 00  MemoryStream
	condition:
		any of ($a_*)
 
}