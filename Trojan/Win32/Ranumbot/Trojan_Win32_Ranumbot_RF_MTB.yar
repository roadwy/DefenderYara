
rule Trojan_Win32_Ranumbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c4 89 84 24 90 01 04 56 33 f6 85 ff 7e 90 01 01 55 8b 2d 90 01 04 e8 90 01 04 30 04 33 83 ff 19 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 90 01 01 e4 33 90 01 01 f0 89 90 01 01 e4 8b 90 01 01 e4 50 8d 90 01 02 51 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RF_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 4d 90 01 01 33 4d 90 01 01 89 4d 90 01 01 83 3d 90 01 04 71 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RF_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff 85 db 7e 90 01 01 56 8b 45 90 01 01 8d 34 07 e8 90 01 04 30 06 83 fb 19 75 90 01 01 33 c0 50 50 50 50 ff 15 90 01 04 47 3b fb 7c 90 00 } //1
		$a_03_1 = {33 f6 85 ff 7e 90 01 01 8d 9b 90 01 04 e8 90 01 04 30 04 33 83 ff 19 75 90 01 01 6a 00 8d 85 90 01 04 50 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 04 46 3b f7 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}