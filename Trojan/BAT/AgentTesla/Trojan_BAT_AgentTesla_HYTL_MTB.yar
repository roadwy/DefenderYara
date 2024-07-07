
rule Trojan_BAT_AgentTesla_HYTL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HYTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {53 74 61 72 5f 41 64 6d 69 72 61 6c } //1 Star_Admiral
		$a_81_1 = {42 61 72 62 61 72 61 } //1 Barbara
		$a_81_2 = {54 6f 43 68 61 72 41 72 72 61 79 } //1 ToCharArray
		$a_81_3 = {50 72 69 65 6e } //1 Prien
		$a_81_4 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {53 70 72 69 6e 67 66 69 65 6c 64 } //1 Springfield
		$a_81_7 = {00 50 6f 73 69 74 69 6f 6e 00 } //1 倀獯瑩潩n
		$a_81_8 = {00 4c 65 76 65 6c 00 } //1
		$a_80_9 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //  1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}