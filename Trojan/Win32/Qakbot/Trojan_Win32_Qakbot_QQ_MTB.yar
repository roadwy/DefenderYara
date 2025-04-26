
rule Trojan_Win32_Qakbot_QQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.QQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 89 45 10 89 55 ?? fe 45 ?? 0f b6 45 ?? 8a 54 08 04 00 55 ff 8d 74 08 ?? 0f b6 45 ?? 8d 7c 08 ?? 8a 44 08 ?? 88 06 03 c2 25 ?? ?? ?? ?? 88 17 8b 55 ?? 8a 44 08 ?? 32 04 1a 88 03 43 ff 4d ?? 75 } //1
		$a_01_1 = {55 70 64 74 } //1 Updt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}