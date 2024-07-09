
rule Trojan_BAT_AgentTesla_LBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 07 08 6f ?? ?? ?? 0a 07 18 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 03 16 03 8e 69 6f ?? ?? ?? 0a 0d de } //1
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c } //1 powershell
		$a_81_3 = {54 65 73 74 2d 4e 65 74 43 6f 6e 6e 65 63 74 69 6f 6e } //1 Test-NetConnection
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}