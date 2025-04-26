
rule Trojan_BAT_AgentTesla_EU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {0d 08 09 61 d1 13 04 06 11 04 6f ?? ?? ?? 0a 26 00 07 17 58 0b 07 02 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d ce 90 09 0d 00 02 07 6f ?? ?? ?? 0a 0c 7e ?? ?? ?? 04 } //10
		$a_81_1 = {41 45 53 5f 44 65 63 72 79 70 74 } //1 AES_Decrypt
		$a_81_2 = {45 6e 63 72 79 70 74 44 65 63 72 79 70 74 } //1 EncryptDecrypt
		$a_81_3 = {58 6f 72 4b 65 79 } //1 XorKey
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_EU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_02_0 = {00 06 07 02 08 6f ?? ?? ?? 0a 9d 06 08 02 07 6f ?? ?? ?? 0a 9d 00 07 17 58 0b 08 17 59 0c 07 08 fe 04 0d 09 2d da } //10
		$a_81_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_81_5 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=15
 
}
rule Trojan_BAT_AgentTesla_EU_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0d 00 00 "
		
	strings :
		$a_81_0 = {24 64 63 33 66 62 39 62 62 2d 35 32 30 64 2d 34 38 61 30 2d 39 62 65 33 2d 38 34 32 31 63 30 37 32 37 33 61 36 } //20 $dc3fb9bb-520d-48a0-9be3-8421c07273a6
		$a_81_1 = {24 38 34 66 63 36 63 31 37 2d 62 63 33 30 2d 34 66 37 63 2d 38 35 64 64 2d 39 35 61 37 61 33 34 35 66 38 32 65 } //20 $84fc6c17-bc30-4f7c-85dd-95a7a345f82e
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_3 = {50 61 73 73 43 72 79 70 74 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 PassCrypt.Resources.resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {6d 50 6f 72 74 61 6c 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //1 mPortal.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_81_12 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=24
 
}