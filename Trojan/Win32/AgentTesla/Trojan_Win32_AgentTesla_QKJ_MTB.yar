
rule Trojan_Win32_AgentTesla_QKJ_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.QKJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 45 ff d1 f8 0f b6 4d ff c1 e1 07 0b c1 88 45 ff 0f b6 45 ff 90 02 05 88 45 ff 0f b6 45 ff 90 00 } //01 00 
		$a_03_1 = {50 6a 40 68 90 01 04 68 18 41 01 10 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}