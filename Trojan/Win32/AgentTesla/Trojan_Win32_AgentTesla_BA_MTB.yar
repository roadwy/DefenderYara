
rule Trojan_Win32_AgentTesla_BA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 02 00 00 00 8b 90 02 02 80 90 01 03 83 90 01 02 3b 90 01 05 7c 90 00 } //1
		$a_02_1 = {0f 6f 06 0f 90 02 02 83 90 02 02 83 90 02 02 e2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_AgentTesla_BA_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f8 40 89 45 f8 81 7d f8 90 01 02 00 00 73 2d 8b 45 f8 33 d2 6a 3b 59 f7 f1 8b 85 90 01 02 ff ff 0f be 04 10 8b 4d f8 0f b6 8c 0d 90 01 02 ff ff 33 c8 8b 45 f8 88 8c 05 90 01 02 ff ff eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}