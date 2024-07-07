
rule Trojan_Win32_Zbot_svfs_MTB{
	meta:
		description = "Trojan:Win32/Zbot.svfs!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 30 8b 45 fc 83 c6 20 03 f0 8b 3e 83 ee 0c 8b 06 03 7d fc 89 45 f4 83 ee 14 33 d2 8b 5d 0c c3 } //10
		$a_01_1 = {83 c6 23 46 b9 02 00 00 00 f7 e1 8b c8 8b 06 03 c8 8b 45 fc 03 c8 0f b7 01 83 ee 24 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 c3 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}