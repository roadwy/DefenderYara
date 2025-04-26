
rule Trojan_Win32_AgentTesla_SR_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 83 fa ff [0-10] b8 ?? ?? 00 00 [0-15] 33 c0 90 05 15 01 90 8b d0 [0-20] 8a 92 ?? ?? ?? 00 88 55 fb 90 05 10 01 90 b2 ?? 90 05 10 01 90 32 55 fb 90 05 10 01 90 88 16 90 05 10 01 90 40 3d ?? ?? 00 00 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}