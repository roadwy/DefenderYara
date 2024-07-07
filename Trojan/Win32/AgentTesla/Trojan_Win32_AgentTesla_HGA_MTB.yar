
rule Trojan_Win32_AgentTesla_HGA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.HGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 75 df c1 fe 90 01 01 0f b6 7d df c1 e7 90 01 01 89 90 01 01 09 90 01 01 88 90 00 } //1
		$a_03_1 = {0f b6 7d df 89 f8 90 02 05 88 45 df 8a 45 df 8b 75 e0 88 04 35 90 02 04 8b 45 e0 83 c0 01 89 45 e0 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}