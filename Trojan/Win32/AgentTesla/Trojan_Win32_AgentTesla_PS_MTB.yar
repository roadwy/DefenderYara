
rule Trojan_Win32_AgentTesla_PS_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 f4 89 45 ec [0-10] 8b 45 08 03 45 f4 89 45 f0 c6 45 fa [0-10] 8b 45 f0 8a 00 88 45 fb [0-0a] 8a 45 fb 88 45 f9 8a 45 f9 32 45 fa 8b 55 ec 88 02 ff 45 f4 81 7d f4 ?? ?? ?? ?? 75 } //1
		$a_03_1 = {8d 45 f0 50 e8 ?? ?? ?? ?? 89 c9 [0-30] 8d 45 e0 50 e8 ?? ?? ?? ?? 89 c9 8d 55 f0 8d 45 e0 e8 ?? ?? ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}