
rule Trojan_BAT_AgentTesla_XSFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.XSFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {03 1f 5a 1f 61 6f ?? ?? ?? 0a 0a 7e 69 00 00 04 06 20 00 01 00 00 14 14 17 8d 3f 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 0b 07 2a } //1
		$a_01_1 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}