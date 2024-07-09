
rule Trojan_Win32_AgentTesla_HGA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.HGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 75 df c1 fe ?? 0f b6 7d df c1 e7 ?? 89 ?? 09 ?? 88 } //1
		$a_03_1 = {0f b6 7d df 89 f8 [0-05] 88 45 df 8a 45 df 8b 75 e0 88 04 35 [0-04] 8b 45 e0 83 c0 01 89 45 e0 e9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}