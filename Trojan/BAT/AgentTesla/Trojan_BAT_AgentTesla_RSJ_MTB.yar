
rule Trojan_BAT_AgentTesla_RSJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RSJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {57 1f b6 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 ea 00 00 00 19 00 00 00 86 00 00 00 81 03 00 00 f5 00 00 00 02 00 00 00 b7 01 00 00 0d 00 00 00 60 02 00 00 56 00 00 00 02 00 00 00 08 00 00 00 0f 00 00 00 60 00 00 00 9e 00 00 00 0f 00 00 00 01 00 00 00 0a 00 00 00 04 00 00 00 0d 00 00 00 06 } //1
		$a_81_1 = {74 72 61 6e 71 75 76 69 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 tranquvis.Properties.Resources.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}