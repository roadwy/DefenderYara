
rule Trojan_Win32_Ranumbot_RTH_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c4 89 84 24 90 01 04 56 33 f6 85 ff 7e 90 01 01 55 8b 6c 24 90 01 01 e8 90 01 04 30 04 33 83 ff 19 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RTH_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e0 01 45 90 01 01 c7 05 90 01 04 36 06 ea e9 8b 90 01 01 e4 33 90 01 01 f0 89 90 01 01 e4 c7 90 02 09 8b 90 01 01 ec 01 90 01 05 8b 90 01 02 33 05 90 01 04 89 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RTH_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e9 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 4d 90 01 01 8b 85 90 01 04 01 45 90 01 01 8b 55 90 01 01 8b 4d 90 01 01 33 d6 33 ca 8d 85 90 01 04 e8 90 01 04 81 c3 90 01 04 83 ad 90 01 04 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Ranumbot_RTH_MTB_4{
	meta:
		description = "Trojan:Win32/Ranumbot.RTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 81 3d 90 01 04 c6 0e 00 00 75 90 00 } //1
		$a_02_1 = {c1 ea 05 8d 0c 38 89 54 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 31 4c 24 90 01 01 83 3d 90 01 04 71 c7 05 90 01 04 36 06 ea e9 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}