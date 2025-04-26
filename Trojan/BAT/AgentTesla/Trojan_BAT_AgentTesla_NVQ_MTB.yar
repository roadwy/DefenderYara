
rule Trojan_BAT_AgentTesla_NVQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_81_0 = {49 4f 55 48 46 53 48 46 49 48 59 55 47 42 43 53 } //3 IOUHFSHFIHYUGBCS
		$a_81_1 = {4f 49 57 44 48 44 4a 57 44 43 48 58 } //3 OIWDHDJWDCHX
		$a_81_2 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //1 ColorTranslator
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_4 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=9
 
}