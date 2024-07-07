
rule Trojan_Win32_AgentTesla_RPP_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 00 8d 14 03 8b 45 f0 01 d0 29 c1 89 ca 8b 45 e4 89 10 8b 45 e4 8b 10 8b 45 e8 89 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}