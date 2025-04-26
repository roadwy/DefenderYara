
rule Trojan_Win32_Qakbot_SAS_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 03 45 ?? 0f b6 08 3a f6 74 ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 66 ?? 74 } //1
		$a_03_1 = {8b 45 ec 03 45 ?? 88 08 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 53 5e f7 f6 66 ?? ?? 74 } //1
		$a_00_2 = {57 69 6e 64 } //1 Wind
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}