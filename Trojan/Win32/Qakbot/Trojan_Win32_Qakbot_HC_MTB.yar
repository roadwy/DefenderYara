
rule Trojan_Win32_Qakbot_HC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d ?? ?? ?? ?? 43 [0-07] 03 d8 43 a1 ?? ?? ?? ?? 33 18 89 1d [0-0b] 8b 1d ?? ?? ?? ?? 2b d8 [0-07] 2b d8 [0-07] 2b d8 a1 ?? ?? ?? ?? 89 18 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}