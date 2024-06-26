
rule Trojan_Win32_Ranumbot_GA_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8d 9b 00 00 00 00 8b 7c 24 14 8b 90 01 01 c1 90 01 01 05 89 4c 24 10 8b 44 24 90 01 01 01 44 24 10 8b 90 01 01 c1 e6 04 03 74 24 20 8d 14 2f 33 90 01 01 81 3d 90 01 08 c7 05 90 01 08 90 18 31 74 24 10 81 3d 90 00 } //0a 00 
		$a_02_1 = {8b 4c 24 10 33 cb 33 ce 8d 44 24 14 e8 90 01 04 81 3d 90 01 08 90 18 81 c5 90 01 04 83 6c 24 18 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3d b2 79 32 00 75 90 01 01 8b 0d 90 01 04 89 0d 90 01 04 40 3d 32 89 93 00 7c 90 01 01 81 05 90 01 04 e1 bf 01 00 33 90 01 01 81 90 01 01 d8 dc 35 00 75 90 01 01 68 90 01 04 ff 15 90 01 04 a3 90 01 05 81 90 01 01 36 bd 5a 00 7c 90 00 } //01 00 
		$a_02_1 = {55 8b ec 51 a1 90 01 04 8b 15 90 01 04 89 45 fc b8 e1 bf 01 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Ranumbot_GA_MTB_3{
	meta:
		description = "Trojan:Win32/Ranumbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 3d b2 79 32 00 75 90 01 01 8b 0d 90 01 04 89 0d 90 01 04 40 3d 32 89 93 00 7c 90 01 01 81 05 90 01 04 e1 bf 01 00 68 90 01 04 56 ff 15 90 01 04 33 90 01 01 81 90 01 01 d8 dc 35 00 75 90 01 01 56 ff 15 90 01 04 a3 90 01 05 81 90 01 01 36 bd 5a 00 7c 90 00 } //01 00 
		$a_02_1 = {55 8b ec 51 a1 90 01 04 8b 15 90 01 04 89 45 fc b8 e1 bf 01 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a c9 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}