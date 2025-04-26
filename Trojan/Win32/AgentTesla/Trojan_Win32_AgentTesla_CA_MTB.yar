
rule Trojan_Win32_AgentTesla_CA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 fb 00 7f [0-10] 89 c2 [0-10] 52 [0-10] c3 90 0a 80 00 bb ?? ?? ?? 00 [0-10] 83 eb 03 [0-06] 83 eb 01 [0-05] ff 34 1f [0-20] 8f 04 18 [0-15] 31 34 18 [0-40] 83 fb 00 7f [0-10] 89 c2 [0-10] 52 [0-10] c3 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}