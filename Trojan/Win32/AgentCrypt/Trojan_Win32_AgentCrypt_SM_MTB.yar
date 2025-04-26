
rule Trojan_Win32_AgentCrypt_SM_MTB{
	meta:
		description = "Trojan:Win32/AgentCrypt.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8d 64 24 ?? 50 e8 00 00 00 00 58 83 c0 ?? 89 45 ?? 58 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 8b 00 89 45 ?? 8b 45 ?? 8b 40 ?? 89 45 } //2
		$a_03_1 = {6a 40 68 00 30 00 00 ff 75 ?? 6a 00 ff 55 ?? 89 45 ?? ff 75 ?? 8b 4d ?? 8b 55 ?? 8b 45 ?? e8 ?? ff ff ff 8d 55 ?? 8b 45 ?? e8 ?? ?? ?? ?? c9 c3 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}