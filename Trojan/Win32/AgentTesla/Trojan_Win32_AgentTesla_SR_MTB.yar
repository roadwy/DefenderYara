
rule Trojan_Win32_AgentTesla_SR_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d2 83 fa ff 90 02 10 b8 90 01 02 00 00 90 02 15 33 c0 90 05 15 01 90 8b d0 90 02 20 8a 92 90 01 03 00 88 55 fb 90 05 10 01 90 b2 90 01 01 90 05 10 01 90 32 55 fb 90 05 10 01 90 88 16 90 05 10 01 90 40 3d 90 01 02 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}