
rule Trojan_Win32_Qakbot_KMG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 e9 15 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 01 00 00 00 85 c9 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}