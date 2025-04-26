
rule Trojan_Win32_Danabot_RF_MTB{
	meta:
		description = "Trojan:Win32/Danabot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 f6 39 74 24 ?? 7e ?? 53 8b 1d ?? ?? ?? ?? 55 8b 2d ?? ?? ?? ?? 57 8b 7c 24 ?? 8d 64 24 ?? 6a 00 ff d5 6a 00 ff d3 e8 ?? ?? ?? ?? 30 04 3e 6a 00 ff d3 6a } //1
		$a_03_1 = {0f af 44 24 ?? c7 04 24 1b 3d 26 00 81 04 24 a8 61 00 00 8b 0c 24 8b 54 24 ?? 03 c8 89 0a 59 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}