
rule Trojan_BAT_AgentTesla_MVB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 07 00 00 0a 72 01 00 00 70 28 08 00 00 0a 0b dd 0d 00 00 00 } //2
		$a_01_1 = {07 28 01 00 00 2b 28 02 00 00 2b 28 0c 00 00 0a 6f 0d 00 00 0a 28 03 00 00 2b 0d } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}