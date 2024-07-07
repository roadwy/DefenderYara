
rule Trojan_Win32_AgentTesla_QJQ_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.QJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 45 e7 0f b6 75 e7 c1 fe 90 01 01 0f b6 7d e7 c1 e7 90 01 01 89 90 01 01 09 90 01 01 88 90 01 01 e7 90 00 } //1
		$a_03_1 = {89 04 24 c7 44 24 04 90 01 04 c7 44 24 08 40 00 00 00 8d 45 f0 89 44 24 0c ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}