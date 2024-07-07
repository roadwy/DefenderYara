
rule Trojan_BAT_AgentTesla_CDN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {ce 00 d0 00 eb 00 cb 00 bb 00 bb 00 c7 00 bb 00 bb 00 bb 00 bb 00 bf 00 bb 00 bb 00 bb 00 bb } //1
		$a_00_1 = {d0 00 c1 00 e2 00 ea 00 dd 00 f3 00 bc 00 f1 00 dd 00 e7 00 b3 00 e8 00 dd 00 e7 00 c0 00 ee 00 c3 00 c1 00 c8 00 e2 00 dc 00 e7 00 af } //1
		$a_81_2 = {00 48 75 6e 74 65 72 00 } //1 䠀湵整r
		$a_81_3 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_5 = {41 72 72 61 79 41 74 74 72 69 62 75 74 65 } //1 ArrayAttribute
		$a_81_6 = {50 61 72 61 6d 41 72 72 61 79 30 } //1 ParamArray0
		$a_81_7 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_81_8 = {47 65 74 43 68 61 72 } //1 GetChar
		$a_81_9 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}