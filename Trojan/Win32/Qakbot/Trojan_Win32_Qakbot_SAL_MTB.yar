
rule Trojan_Win32_Qakbot_SAL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 e3 bb 00 00 00 00 e9 ?? ?? ?? ?? 8b 45 ?? 0f b6 44 10 ?? 33 c8 3a f6 74 ?? 8b 45 ?? 03 45 ?? 0f b6 08 3a c0 74 } //1
		$a_00_1 = {57 69 6e 64 } //1 Wind
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}