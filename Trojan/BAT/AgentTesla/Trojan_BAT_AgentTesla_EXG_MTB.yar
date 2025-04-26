
rule Trojan_BAT_AgentTesla_EXG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EXG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 00 24 00 4d 00 4c 00 4b 00 6a 00 63 00 6c 00 6b 00 64 00 73 00 6a 00 66 00 6b 00 6c 00 73 00 64 00 66 00 6b 00 67 00 68 00 66 00 64 00 6b 00 68 00 67 00 66 00 68 00 6d 00 6a 00 6c 00 79 00 69 00 6c 00 24 00 24 00 } //1 $$MLKjclkdsjfklsdfkghfdkhgfhmjlyil$$
		$a_01_1 = {41 00 53 00 41 00 4d 00 65 00 74 00 68 00 6f 00 64 00 30 00 41 00 53 00 41 00 } //1 ASAMethod0ASA
		$a_01_2 = {24 00 24 00 4e 00 6f 00 42 00 6f 00 64 00 79 00 43 00 61 00 6e 00 47 00 65 00 74 00 49 00 74 00 24 00 24 00 } //1 $$NoBodyCanGetIt$$
		$a_81_3 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //1 GetExportedTypes
		$a_01_4 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_81_5 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}