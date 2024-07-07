
rule Trojan_BAT_AgentTesla_OC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.OC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {56 e4 6e 64 74 69 61 5f 4c 69 76 65 5f 53 65 72 76 65 72 2e 46 6f 72 6d 4c 6f 61 64 65 72 } //1
		$a_81_1 = {6e 64 74 69 61 5f 4c 69 76 65 5f 53 65 72 76 65 72 2e 4d 79 } //1 ndtia_Live_Server.My
		$a_81_2 = {43 61 72 64 49 6e 66 6f 46 6f 72 6d } //1 CardInfoForm
		$a_81_3 = {54 69 6d 65 72 31 } //1 Timer1
		$a_81_4 = {53 74 72 52 65 76 65 72 73 65 } //1 StrReverse
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {54 65 78 74 42 6f 78 31 } //1 TextBox1
		$a_81_7 = {46 6f 72 4c 6f 6f 70 49 6e 69 74 4f 62 6a } //1 ForLoopInitObj
		$a_81_8 = {52 65 61 64 42 79 74 65 } //1 ReadByte
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}