
rule Trojan_Win32_Keylogger_RPN_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 45 f6 89 04 24 e8 ?? ?? ?? ?? 83 ec 04 66 3d 01 80 0f 94 c0 84 c0 74 3d c7 44 24 04 ?? ?? ?? ?? c7 04 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 e8 0f b7 45 f6 89 44 24 08 c7 44 24 04 ?? ?? ?? ?? 8b 45 e8 89 04 24 e8 ?? ?? ?? ?? 8b 45 e8 89 04 24 e8 ?? ?? ?? ?? 66 ff 45 f4 66 ff 45 f6 66 83 7d f4 31 0f 96 c0 84 c0 75 95 c7 04 24 01 00 00 00 e8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}