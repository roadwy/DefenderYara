
rule Trojan_BAT_AgentTesla_GQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_02_0 = {14 0b 14 0c 19 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 a2 0c 08 17 28 ?? ?? ?? 06 a2 08 18 72 ?? ?? ?? 70 a2 02 7b ?? ?? ?? 04 08 28 ?? ?? ?? 0a 26 08 18 9a 0a 2b 00 06 2a } //10
		$a_02_1 = {03 16 1a 6f ?? ?? ?? 0a 0b 14 0c 14 0d 19 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 a2 0d 09 17 28 ?? ?? ?? 06 a2 09 18 72 ?? ?? ?? 70 a2 02 7b ?? ?? ?? 04 09 28 ?? ?? ?? 0a 26 07 07 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a } //10
		$a_81_2 = {47 65 74 46 69 6c 65 4e 61 6d 65 42 79 55 52 4c } //1 GetFileNameByURL
		$a_81_3 = {69 6d 69 6d 69 6d 69 6d 69 6d } //1 imimimimim
		$a_81_4 = {00 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 78 00 } //1 砀硸硸硸硸硸硸硸硸x
		$a_81_5 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=16
 
}