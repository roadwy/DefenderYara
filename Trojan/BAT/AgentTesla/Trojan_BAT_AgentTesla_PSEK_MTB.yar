
rule Trojan_BAT_AgentTesla_PSEK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {09 69 8d a7 00 00 01 25 17 73 26 00 00 0a 13 04 06 6f 27 00 00 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f 23 00 00 06 2a } //5
		$a_01_1 = {49 45 6e 75 6d 65 72 61 62 6c 65 } //1 IEnumerable
		$a_01_2 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_3 = {42 6c 6f 63 6b 43 6f 70 79 } //1 BlockCopy
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}