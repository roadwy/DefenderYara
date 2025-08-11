
rule Trojan_BAT_AgentTesla_NCQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 07 6f 0a 00 00 0a 00 00 de 0b 08 2c 07 08 ?? ?? ?? ?? ?? 00 dc 07 ?? ?? ?? ?? ?? 0d 2b 00 09 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_NCQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 1f 41 08 58 d1 0d 12 03 28 ab 00 00 0a 72 a4 0b 00 70 07 08 8f 73 00 00 01 28 ac 00 00 0a 28 ad 00 00 0a 13 04 04 07 08 91 6f ae 00 00 0a 00 00 08 17 58 0c 08 03 fe 04 13 05 11 05 2d c1 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}