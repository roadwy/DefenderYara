
rule Trojan_BAT_AgentTesla_BQF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_02_0 = {06 20 00 01 00 00 6f ?? ?? ?? 0a 00 06 20 80 00 00 00 6f ?? ?? ?? 0a 00 7e ?? ?? ?? 04 7e ?? ?? ?? 04 20 e8 03 00 00 73 ?? ?? ?? 0a 0b 06 07 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 07 06 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 06 17 6f } //10
		$a_81_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_81_2 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 74 68 6f 64 } //1 InvokeMethod
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //1 ClassLibrary
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=12
 
}