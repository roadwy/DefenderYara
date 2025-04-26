
rule Trojan_Win32_AgentTesla_ZAA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 75 e7 c1 fe [0-01] 0f b6 7d e7 c1 e7 [0-01] 89 [0-01] 09 [0-01] 88 [0-01] e7 0f b6 75 e7 89 [0-01] 83 [0-02] 88 [0-01] e7 0f b6 75 e7 } //1
		$a_03_1 = {89 04 24 c7 44 24 04 ?? ?? ?? ?? c7 44 24 08 40 00 00 00 8d 45 f0 89 44 24 0c ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}