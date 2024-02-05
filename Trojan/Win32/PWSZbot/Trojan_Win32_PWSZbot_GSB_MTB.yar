
rule Trojan_Win32_PWSZbot_GSB_MTB{
	meta:
		description = "Trojan:Win32/PWSZbot.GSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 70 60 8b 45 fc 03 c6 83 c0 90 01 01 8b f0 8b 38 b8 0c 00 00 00 2b f0 8b 06 03 7d fc 89 45 f4 83 ee 90 01 01 33 d2 8b 5d 0c c3 90 00 } //0a 00 
		$a_01_1 = {8b d1 8b 5d f0 33 c0 42 8b 0a 40 fe c1 fe c9 75 f6 48 c3 } //00 00 
	condition:
		any of ($a_*)
 
}