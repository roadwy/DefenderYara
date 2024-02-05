
rule Trojan_Win32_AgentTesla_ZAA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 75 e7 c1 fe 90 02 01 0f b6 7d e7 c1 e7 90 02 01 89 90 02 01 09 90 02 01 88 90 02 01 e7 0f b6 75 e7 89 90 02 01 83 90 02 02 88 90 02 01 e7 0f b6 75 e7 90 00 } //01 00 
		$a_03_1 = {89 04 24 c7 44 24 04 90 01 04 c7 44 24 08 40 00 00 00 8d 45 f0 89 44 24 0c ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}