
rule Trojan_Win32_AgentTesla_ZAB_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ZAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 45 ff c1 f8 90 02 01 0f b6 4d ff c1 e1 90 02 01 0b c1 88 45 ff 0f b6 45 ff 90 02 03 88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 90 00 } //01 00 
		$a_03_1 = {8d 45 f0 50 6a 40 68 90 01 04 68 78 8c 00 10 ff 15 44 70 00 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}