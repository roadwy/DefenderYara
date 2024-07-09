
rule Trojan_Win32_Qakbot_EQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 48 8b 55 ?? 33 02 89 45 ?? 8b 45 ?? 8b 55 ?? 89 02 33 c0 89 45 ?? 8b 45 ?? 83 c0 04 03 45 ?? 89 45 ?? 6a 00 e8 ?? ?? ?? ?? 8b 5d ?? 83 c3 04 03 5d ?? 2b d8 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}