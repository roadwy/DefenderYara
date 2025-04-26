
rule Trojan_BAT_AgentTesla_NCB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 02 08 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 28 19 00 00 0a 6f 1a 00 00 0a 26 08 18 d6 0c 08 07 31 dd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}