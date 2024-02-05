
rule Trojan_Win32_Zbot_RQIJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RQIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 03 8b 70 60 8b 45 fc 83 c0 20 03 f0 8b 3e 83 ee 90 01 01 8b 06 03 7d fc 89 45 f4 83 ee 90 01 01 33 d2 8b 5d 0c c3 90 00 } //0a 00 
		$a_02_1 = {8b 45 fc 03 c8 0f b7 01 83 ee 90 01 01 8b 4e 1c 8d 04 81 8b 4d fc 8b 04 01 90 00 } //01 00 
		$a_01_2 = {76 63 78 74 52 34 6f 65 4d } //00 00 
	condition:
		any of ($a_*)
 
}