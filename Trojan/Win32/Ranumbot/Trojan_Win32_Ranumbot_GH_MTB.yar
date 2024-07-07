
rule Trojan_Win32_Ranumbot_GH_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 10 8b 84 24 90 01 04 01 44 24 10 8d 0c 37 31 4c 24 90 01 01 81 3d 90 01 08 c7 05 90 01 08 90 18 8b 54 24 90 01 01 31 54 24 90 01 01 83 3d 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Ranumbot_GH_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 4c 24 90 01 01 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8d 04 33 31 44 24 90 01 01 81 3d 90 01 08 c7 05 90 01 08 90 18 8b 44 24 90 01 01 31 44 24 90 01 01 83 3d 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}