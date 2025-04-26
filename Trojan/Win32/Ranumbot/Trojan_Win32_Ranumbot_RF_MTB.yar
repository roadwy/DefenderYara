
rule Trojan_Win32_Ranumbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 8b ?? e4 50 8d ?? ?? 51 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 83 3d ?? ?? ?? ?? 71 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff 85 db 7e ?? 56 8b 45 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 fb 19 75 ?? 33 c0 50 50 50 50 ff 15 ?? ?? ?? ?? 47 3b fb 7c } //1
		$a_03_1 = {33 f6 85 ff 7e ?? 8d 9b ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75 ?? 6a 00 8d 85 ?? ?? ?? ?? 50 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}