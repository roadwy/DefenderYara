
rule Trojan_BAT_AgentTesla_DXD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 6c 23 ff b9 f4 ee 2a 81 f7 3f 5b 28 ?? ?? ?? 06 b7 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0b 07 0a } //1
		$a_01_1 = {69 00 66 00 75 00 5f 00 54 00 65 00 } //1 ifu_Te
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}