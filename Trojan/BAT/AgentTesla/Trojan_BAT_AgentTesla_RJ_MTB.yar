
rule Trojan_BAT_AgentTesla_RJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {18 8d 09 00 00 01 25 16 11 01 a2 25 17 11 02 a2 13 04 38 } //1
		$a_03_1 = {03 14 fe 03 39 28 00 00 00 38 13 00 00 00 03 02 7b ?? 00 00 04 fe 01 39 e4 ff ff ff 38 ?? ?? ?? ?? 20 ?? ?? ?? ?? 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}