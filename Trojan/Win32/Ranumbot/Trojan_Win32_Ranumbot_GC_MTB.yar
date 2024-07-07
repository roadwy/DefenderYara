
rule Trojan_Win32_Ranumbot_GC_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 33 c0 3b ce 90 01 02 8b 3d 90 01 04 90 18 8a 94 07 90 01 04 8b 1d 90 01 04 88 14 03 81 f9 90 01 04 90 18 40 3b c1 90 00 } //10
		$a_80_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  10
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Ranumbot_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Ranumbot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c1 01 89 4d 90 01 01 8b 55 90 01 01 8b 45 90 01 01 3b 82 90 01 04 73 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 8b 45 90 01 01 03 45 90 01 01 0f b6 08 33 90 01 01 8b 55 90 01 01 03 55 90 01 01 88 0a 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}