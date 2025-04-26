
rule Trojan_Win32_Qakbot_AJ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 45 e0 89 45 dc 8b 45 f0 03 45 e0 89 45 f0 8b 45 ec 2b 45 e0 89 45 ec 83 7d e0 00 76 90 0a 50 00 ff 75 ?? ff 75 ?? 8b 45 ?? 8b 40 ?? 8b 4d ?? 8b 00 8b 49 ?? ff 50 ?? 89 45 ?? 8b 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Qakbot_AJ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 66 3b db 74 ?? c6 45 ?? 65 66 3b ?? 74 ?? c6 45 ?? 73 66 3b ?? 74 ?? c6 45 ?? 74 3a ?? 74 ?? c6 45 ?? 52 66 3b ?? 74 ?? c6 45 ?? 67 66 3b ?? 74 ?? c6 45 ?? 65 66 3b ?? 74 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}