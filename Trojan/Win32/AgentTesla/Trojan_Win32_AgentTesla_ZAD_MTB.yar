
rule Trojan_Win32_AgentTesla_ZAD_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.ZAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 45 ff c1 f8 90 01 01 0f b6 4d ff 90 02 03 0b c1 88 45 ff 0f b6 45 ff 90 02 03 88 45 ff 0f b6 45 ff 90 02 03 88 45 ff 0f b6 45 ff 90 00 } //01 00 
		$a_03_1 = {8d 45 f0 50 6a 40 68 90 01 04 68 10 50 00 10 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}