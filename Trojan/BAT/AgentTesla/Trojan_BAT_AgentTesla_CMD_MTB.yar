
rule Trojan_BAT_AgentTesla_CMD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 42 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 42 00 } //10 䈀彟彟彟彟彟彟彟彟彟彟彟彟B
		$a_01_1 = {53 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 53 00 4d 65 73 73 61 67 65 } //10 当彟彟彟彟彟彟彟彟彟彟彟彟彟卟䴀獥慳敧
		$a_01_2 = {54 6f 49 6e 74 33 32 } //1 ToInt32
		$a_01_3 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //1 GetTypeFromHandle
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}