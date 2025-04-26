
rule Trojan_Win32_Qakbot_HE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 03 45 f0 0f b6 08 3a f6 74 ?? 8b 45 fc 0f b6 44 10 10 33 c8 66 3b ed 74 ?? 8b 45 ec 03 45 f0 88 08 e9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 53 5e f7 f6 66 3b c0 74 } //1
		$a_01_1 = {77 69 6e 64 } //1 wind
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}