
rule Trojan_Win32_AgentTesla_DSK_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c1 83 e1 03 8a 4c 0c 04 30 88 90 01 04 40 3d 05 5a 00 00 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}