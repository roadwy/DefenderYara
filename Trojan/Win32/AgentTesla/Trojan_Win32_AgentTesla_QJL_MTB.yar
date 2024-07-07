
rule Trojan_Win32_AgentTesla_QJL_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.QJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 45 ff 0f b6 45 ff c1 f8 90 01 01 0f b6 4d ff c1 e1 90 01 01 0b c1 88 45 ff 0f b6 45 ff 90 02 05 88 45 ff 0f b6 45 ff 90 00 } //1
		$a_03_1 = {8d 45 f0 50 6a 40 68 90 01 04 68 68 a0 00 10 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}