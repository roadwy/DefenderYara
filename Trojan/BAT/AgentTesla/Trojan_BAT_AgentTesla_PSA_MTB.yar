
rule Trojan_BAT_AgentTesla_PSA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 a4 00 00 00 1f 00 00 00 } //5
		$a_01_1 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {41 54 4d 4d 61 6e 61 67 65 72 2e 55 70 64 61 74 65 2e 72 65 73 6f 75 72 63 65 73 } //1 ATMManager.Update.resources
		$a_01_5 = {67 65 74 5f 43 61 72 64 4e 75 6d } //1 get_CardNum
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=10
 
}