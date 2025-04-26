
rule Trojan_Win32_AgentTesla_RPE_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPE!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 33 47 4f 93 93 30 13 90 90 90 30 23 fc 30 03 f9 43 90 e2 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}