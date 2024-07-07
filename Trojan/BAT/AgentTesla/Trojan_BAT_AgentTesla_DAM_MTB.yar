
rule Trojan_BAT_AgentTesla_DAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 09 1f 41 59 1f 0a 58 d1 13 09 2b 08 11 09 1f 30 59 d1 13 09 09 11 07 1f 10 11 08 5a 11 09 58 d2 9c 00 11 07 17 58 13 07 11 07 08 fe 04 13 0c 11 0c 2d 84 } //4
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=4
 
}