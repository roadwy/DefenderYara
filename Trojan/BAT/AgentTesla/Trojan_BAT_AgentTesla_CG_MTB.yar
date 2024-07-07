
rule Trojan_BAT_AgentTesla_CG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {03 07 03 07 91 02 04 07 04 8e b7 5d 91 04 04 07 04 8e b7 5d 91 04 8e b7 5d 91 6f } //1
		$a_01_1 = {61 04 07 07 1d 5d d6 04 8e b7 5d 04 8e b7 5d 91 61 9c 07 17 d6 0b 07 08 31 } //1
		$a_01_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 4b 00 45 00 59 00 } //1 EncryptionKEY
		$a_01_3 = {58 6f 72 43 72 79 70 74 } //1 XorCrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_BAT_AgentTesla_CG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_81_0 = {47 61 6d 65 42 61 63 6b 75 70 4d 61 6e 61 67 65 72 } //1 GameBackupManager
		$a_81_1 = {41 5a 58 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 43 } //1 AZXCCCCCCCCCCCCCCCCCCC
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_3 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_5 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_6 = {47 5a 69 70 53 74 72 65 61 6d } //1 GZipStream
		$a_81_7 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_9 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_10 = {69 6d 69 6d 69 6d 69 6d 69 6d } //1 imimimimim
		$a_81_11 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //1 砀硸硸硸硸硸硸硸硸x
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=12
 
}