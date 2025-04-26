
rule Trojan_Win32_AgentTesla_PC_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.PC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 7c b4 08 0f b6 d2 89 7c 8c 08 89 54 b4 08 8b 7c 8c 08 03 fa 81 e7 ff 00 00 80 79 ?? 4f 81 cf 00 ff ff ff 47 0f b6 54 bc 08 30 90 90 ?? ?? ?? 00 41 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 8b 54 8c 08 03 f2 81 e6 ff 00 00 80 79 } //1
		$a_02_1 = {8a 54 8c 0c 8b 7c b4 08 0f b6 d2 89 7c 8c 0c 89 54 b4 08 8b d0 83 e2 1f 0f b6 92 ?? ?? ?? 00 03 54 8c 10 03 f2 81 e6 ff 00 00 80 79 ?? 4e 81 ce 00 ff ff ff 46 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}