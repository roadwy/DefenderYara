
rule Trojan_Win32_Qakbot_MR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 8b 55 08 8b 02 83 c0 ?? 8b 4d 08 89 01 8b 55 08 8b 02 83 e8 ?? 8b 4d 08 89 01 5e 8b e5 5d c3 } //1
		$a_02_1 = {89 08 5b 5d c3 90 0a 2d 00 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 01 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}