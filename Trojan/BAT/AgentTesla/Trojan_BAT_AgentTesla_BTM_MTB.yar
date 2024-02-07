
rule Trojan_BAT_AgentTesla_BTM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {49 73 61 61 63 43 6f 72 65 00 43 6f 72 65 } //01 00  獉慡䍣牯e潃敲
		$a_81_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //01 00  RijndaelManaged
		$a_81_2 = {43 72 79 70 74 6f 53 74 72 65 61 6d 4d 6f 64 65 } //01 00  CryptoStreamMode
		$a_81_3 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_81_4 = {4b 65 79 53 69 7a 65 } //01 00  KeySize
		$a_81_5 = {42 6c 6f 63 6b 53 69 7a 65 } //01 00  BlockSize
		$a_81_6 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_81_7 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_8 = {61 64 64 5f 41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //01 00  add_AssemblyResolve
		$a_81_9 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //00 00  GetTypeFromHandle
	condition:
		any of ($a_*)
 
}