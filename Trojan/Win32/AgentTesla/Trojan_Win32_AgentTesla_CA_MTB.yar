
rule Trojan_Win32_AgentTesla_CA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 fb 00 7f 90 02 10 89 c2 90 02 10 52 90 02 10 c3 90 0a 80 00 bb 90 01 03 00 90 02 10 83 eb 03 90 02 06 83 eb 01 90 02 05 ff 34 1f 90 02 20 8f 04 18 90 02 15 31 34 18 90 02 40 83 fb 00 7f 90 02 10 89 c2 90 02 10 52 90 02 10 c3 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}