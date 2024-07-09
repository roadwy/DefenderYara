
rule Trojan_Win32_Qakbot_DF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 ca 2b 0d ?? ?? ?? ?? 81 c1 5c 45 01 00 0f b6 d2 89 0d ?? ?? ?? ?? 0f b6 cb 0f af d1 02 54 24 10 89 54 24 14 88 15 ?? ?? ?? ?? 8d 56 ff 8b 74 24 18 8b 0e 81 c1 70 36 08 01 89 0e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DF_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 02 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}