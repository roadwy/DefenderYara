
rule Trojan_Win32_Qakbot_EU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 6a 66 e8 ?? ?? ?? ?? 2b d8 6a 66 e8 ?? ?? ?? ?? 03 d8 89 5d ?? 8b 45 ?? 8b 55 d8 01 02 8b 45 ?? 03 45 ?? 8b 55 ?? 31 02 83 45 ec 04 83 45 d8 04 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}