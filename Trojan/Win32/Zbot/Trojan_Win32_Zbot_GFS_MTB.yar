
rule Trojan_Win32_Zbot_GFS_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 0f 8a e9 32 c5 fe c1 } //10
		$a_01_1 = {8b 45 fc 83 c0 20 03 f0 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3 c3 } //10
		$a_80_2 = {5c 31 2e 73 63 72 } //\1.scr  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_80_2  & 1)*1) >=21
 
}