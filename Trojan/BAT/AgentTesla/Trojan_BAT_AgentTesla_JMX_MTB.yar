
rule Trojan_BAT_AgentTesla_JMX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 00 32 00 4d 00 67 00 63 00 47 00 39 00 33 00 5a 00 58 00 4a 00 7a 00 61 00 47 00 56 00 73 00 } //10 L2MgcG93ZXJzaGVs
		$a_01_1 = {62 00 43 00 41 00 74 00 51 00 32 00 39 00 74 00 62 00 57 00 46 00 75 00 5a 00 43 00 42 00 42 00 } //10 bCAtQ29tbWFuZCBB
		$a_01_2 = {5a 00 47 00 51 00 74 00 54 00 58 00 42 00 51 00 63 00 6d 00 56 00 6d 00 5a 00 58 00 4a 00 6c 00 } //10 ZGQtTXBQcmVmZXJl
		$a_01_3 = {62 00 6d 00 4e 00 6c 00 49 00 43 00 31 00 46 00 65 00 47 00 4e 00 73 00 64 00 58 00 4e 00 70 00 } //10 bmNlIC1FeGNsdXNp
		$a_81_4 = {47 65 74 53 74 72 69 6e 67 } //1 GetString
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_6 = {72 75 6e 61 73 } //1 runas
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=23
 
}