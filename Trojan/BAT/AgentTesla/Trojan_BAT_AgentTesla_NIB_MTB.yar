
rule Trojan_BAT_AgentTesla_NIB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {07 09 06 09 18 5a 18 6f 90 01 03 0a 1f 10 28 90 01 03 0a 9c 09 17 58 0d 09 20 00 58 00 00 fe 04 13 04 11 04 2d da 90 00 } //1
		$a_01_1 = {53 75 62 73 74 72 69 6e 67 } //1 Substring
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //1 GetExecutingAssembly
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}