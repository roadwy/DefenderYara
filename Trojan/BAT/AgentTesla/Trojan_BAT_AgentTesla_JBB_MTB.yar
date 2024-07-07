
rule Trojan_BAT_AgentTesla_JBB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_81_0 = {61 62 62 39 37 63 66 62 2d 39 37 32 65 2d 34 39 34 65 2d 62 37 65 35 2d 62 61 62 37 63 36 65 38 63 61 66 63 } //1 abb97cfb-972e-494e-b7e5-bab7c6e8cafc
		$a_81_1 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_2 = {49 6e 74 65 72 6e 61 6c 54 61 73 6b 53 74 6f 70 70 65 64 } //1 InternalTaskStopped
		$a_81_3 = {43 68 65 63 6b 46 6f 72 53 79 6e 63 4c 6f 63 6b 4f 6e 56 61 6c 75 65 54 79 70 65 } //1 CheckForSyncLockOnValueType
		$a_81_4 = {49 45 78 70 61 6e 64 6f 2e 50 6c 75 67 } //1 IExpando.Plug
		$a_81_5 = {46 49 4c 45 49 44 } //1 FILEID
		$a_81_6 = {47 65 74 44 6f 6d 61 69 6e } //1 GetDomain
		$a_81_7 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //1 GetObjectValue
		$a_81_8 = {43 3a 5c 54 65 6d 70 5c } //1 C:\Temp\
		$a_81_9 = {46 6f 72 6d 31 5f 46 6f 72 6d 43 6c 6f 73 69 6e 67 } //1 Form1_FormClosing
		$a_81_10 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_11 = {54 6f 43 68 61 72 41 72 72 61 79 52 61 6e 6b 4f 6e 65 } //1 ToCharArrayRankOne
		$a_81_12 = {6d 65 73 73 61 67 65 43 6f 6e 74 72 6f 6c 6c 65 72 } //1 messageController
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1) >=13
 
}