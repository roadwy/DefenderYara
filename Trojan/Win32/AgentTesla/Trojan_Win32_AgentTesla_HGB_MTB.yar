
rule Trojan_Win32_AgentTesla_HGB_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.HGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c0 4a 88 45 ff 0f b6 45 ff c1 f8 05 0f b6 4d ff c1 e1 03 0b c1 88 45 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 45 ff 03 45 f8 88 45 ff 8b 45 f8 8a 4d ff 88 88 90 01 04 e9 90 00 } //01 00 
		$a_03_1 = {0f b6 45 ff f7 d8 88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff 03 45 f8 88 45 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 45 ff f7 d0 88 45 ff 0f b6 45 ff 83 e8 6a 88 45 ff 8b 45 f8 8a 4d ff 88 88 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}