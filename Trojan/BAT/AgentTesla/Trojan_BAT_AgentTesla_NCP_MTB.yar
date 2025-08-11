
rule Trojan_BAT_AgentTesla_NCP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 02 07 6f ?? ?? ?? 0a 03 07 1f 10 5d 91 61 07 20 ff 00 00 00 5d d1 61 d1 9d 07 17 58 0b 07 02 6f 20 00 00 0a 32 d8 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_BAT_AgentTesla_NCP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 02 8e 69 8d 30 00 00 01 0a 16 0b 2b 15 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 06 0d 2b 00 09 2a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}