
rule Trojan_BAT_AgentTesla_LNC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {61 65 30 63 39 37 39 31 2d 62 65 33 36 2d 34 30 38 66 2d 39 39 64 62 2d 34 34 35 38 35 33 39 36 61 30 62 31 } //1 ae0c9791-be36-408f-99db-44585396a0b1
		$a_01_1 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_01_7 = {54 72 69 6e 69 74 79 } //1 Trinity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_LNC_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.LNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_01_0 = {24 36 61 34 65 61 32 61 65 2d 36 38 65 61 2d 34 33 36 39 2d 62 62 61 31 2d 62 33 34 62 39 33 37 64 65 62 37 36 } //20 $6a4ea2ae-68ea-4369-bba1-b34b937deb76
		$a_01_1 = {24 35 36 31 32 65 30 61 32 2d 62 66 35 62 2d 34 38 65 61 2d 61 61 61 38 2d 34 37 65 64 37 62 64 39 32 34 31 33 } //20 $5612e0a2-bf5b-48ea-aaa8-47ed7bd92413
		$a_01_2 = {52 43 32 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 RC2CryptoServiceProvider
		$a_01_3 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_5 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=27
 
}