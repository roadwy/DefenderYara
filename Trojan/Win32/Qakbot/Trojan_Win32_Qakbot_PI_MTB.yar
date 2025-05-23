
rule Trojan_Win32_Qakbot_PI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 31 31 38 64 65 38 31 62 33 30 31 33 31 64 36 63 63 33 33 61 31 35 34 30 32 37 33 31 30 33 37 } //1 e118de81b30131d6cc33a15402731037
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_PI_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 57 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 89 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 8b 02 a3 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 83 e9 01 89 0d ?? ?? ?? 00 8b 0d ?? ?? ?? 00 83 c1 01 a1 ?? ?? ?? 00 a3 ?? ?? ?? 00 a1 ?? ?? ?? 00 31 0d ?? ?? ?? 00 8b ff c7 05 ?? ?? ?? 00 00 00 00 00 a1 ?? ?? ?? 00 01 05 ?? ?? ?? 00 8b ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 89 02 5f 5d c3 } //10
		$a_02_1 = {8b 45 fc 3b 05 ?? ?? ?? 00 72 ?? eb ?? eb ?? 8b 4d fc 89 4d ?? 8b 15 ?? ?? ?? 00 03 55 fc 89 15 ?? ?? ?? 00 8b 45 ?? 89 45 ?? 8b 4d ?? 51 6a 2d e8 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1) >=11
 
}