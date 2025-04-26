
rule Trojan_BAT_AgentTesla_SY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 17 58 13 07 06 20 c0 e1 00 00 5d 13 04 07 11 04 91 13 08 06 1f 16 5d 13 09 07 11 04 11 08 1f 16 8d 06 00 00 01 25 d0 15 00 00 04 28 0f 01 00 0a 11 09 91 61 07 11 07 20 c0 e1 00 00 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 06 17 58 0a 06 20 c0 e1 00 00 fe 04 13 0a 11 0a 2d a0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}