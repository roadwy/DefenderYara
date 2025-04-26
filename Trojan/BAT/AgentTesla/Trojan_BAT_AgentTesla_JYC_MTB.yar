
rule Trojan_BAT_AgentTesla_JYC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JYC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {69 53 6e 74 69 79 44 74 76 4f 77 59 4a } //1 iSntiyDtvOwYJ
		$a_01_1 = {41 72 53 65 65 } //1 ArSee
		$a_81_2 = {41 34 41 53 46 41 47 46 } //1 A4ASFAGF
		$a_01_3 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_4 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_5 = {66 72 6d 42 61 73 65 53 46 } //1 frmBaseSF
		$a_01_6 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_01_7 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_8 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_9 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}