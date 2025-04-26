
rule Trojan_BAT_AgentTesla_NQJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 11 04 07 11 04 07 8e 69 5d 91 06 11 04 91 61 d2 9c 00 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d d9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_NQJ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {31 38 2e 31 37 39 2e 31 31 31 2e 32 34 30 2f 31 62 31 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f } //1 18.179.111.240/1b1/loader/uploads/
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {47 65 74 52 65 73 70 6f 6e 73 65 } //1 GetResponse
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}