
rule Trojan_Win32_Lokibot_I_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff } //1
		$a_02_1 = {8b 45 f8 03 45 f0 89 45 ec [0-7f] 25 ff 00 00 00 89 84 bd ?? ?? ff ff [0-2f] 8a 02 88 45 e7 [0-4f] 8a 84 85 ?? ?? ff ff 32 45 e7 8b 4d ec 88 01 [0-4f] ff 45 f0 42 ff 4d e0 0f 85 ?? ff ff ff } //5
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*5) >=6
 
}