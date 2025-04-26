
rule Trojan_BAT_AgentTesla_BOD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BOD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0b 00 00 "
		
	strings :
		$a_81_0 = {46 45 41 39 34 41 35 30 2d 45 35 43 38 2d 34 65 64 64 2d 42 45 36 32 2d 46 37 33 38 42 43 38 43 30 34 33 45 } //20 FEA94A50-E5C8-4edd-BE62-F738BC8C043E
		$a_81_1 = {42 69 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 BinaryOperation
		$a_81_2 = {50 65 78 65 73 6f 43 6f 72 65 2e 64 6c 6c } //1 PexesoCore.dll
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetMethodFromHandle
		$a_81_5 = {54 6f 55 49 6e 74 33 32 } //1 ToUInt32
		$a_81_6 = {55 6e 61 72 79 4f 70 65 72 61 74 69 6f 6e } //1 UnaryOperation
		$a_81_7 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_8 = {44 45 53 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 DESCryptoServiceProvider
		$a_81_9 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_81_10 = {52 65 71 75 65 73 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 RequestingAssembly
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1) >=30
 
}