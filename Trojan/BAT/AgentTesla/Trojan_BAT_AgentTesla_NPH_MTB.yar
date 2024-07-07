
rule Trojan_BAT_AgentTesla_NPH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 02 09 18 6f 78 00 00 0a 1f 10 28 c7 00 00 0a 28 c8 00 00 0a 6f c9 00 00 0a 26 09 18 d6 0d 09 08 31 dd } //1
		$a_01_1 = {5f 30 30 30 30 30 30 30 30 30 30 35 } //1 _00000000005
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}