
rule Trojan_BAT_AgentTesla_OU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {06 11 04 6f [0-04] 06 18 6f [0-04] 02 6f [0-04] 16 02 6f [0-04] 28 [0-04] 0c 28 [0-04] 06 6f [0-04] 08 16 08 8e 69 6f [0-04] 6f [0-04] 0b } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_3 = {43 6f 6d 70 75 74 65 48 61 73 68 } //1 ComputeHash
		$a_81_4 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}