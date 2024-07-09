
rule Trojan_BAT_AgentTesla_PB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {26 09 16 28 [0-04] 13 ?? 07 14 72 [0-04] 17 8d [0-04] 25 16 16 8c [0-04] a2 14 14 28 [0-05] 11 ?? 17 da 17 d6 8d [0-04] 13 ?? 08 14 72 [0-04] 19 8d [0-04] 25 16 11 ?? a2 25 17 16 8c [0-04] a2 25 18 [0-02] 8c [0-04] a2 } //1
		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}