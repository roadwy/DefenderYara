
rule Trojan_Win32_Qakbot_RTC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? bb 00 00 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? 04 81 2d ?? ?? ?? ?? 00 10 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}