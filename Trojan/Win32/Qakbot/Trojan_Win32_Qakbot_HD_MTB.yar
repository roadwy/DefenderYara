
rule Trojan_Win32_Qakbot_HD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 6a 00 e8 ?? ?? ?? ?? 2b d8 a1 ?? ?? ?? ?? 89 18 a1 ?? ?? ?? ?? 83 c0 04 a3 ?? ?? ?? ?? 33 c0 a3 90 09 17 00 01 10 a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}