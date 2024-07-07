
rule Trojan_Win32_AgentTesla_ZBA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ZBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 fa 02 0f b6 05 90 01 04 c1 e0 06 0b d0 88 15 90 01 04 0f b6 0d 90 01 04 33 0d 90 01 04 88 0d 90 01 04 0f b6 15 90 09 0d 00 88 0d 90 01 04 0f b6 15 90 00 } //1
		$a_03_1 = {50 6a 40 68 90 01 04 68 90 01 04 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}