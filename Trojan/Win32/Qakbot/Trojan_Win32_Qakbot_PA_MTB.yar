
rule Trojan_Win32_Qakbot_PA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 75 f4 03 c6 03 45 f4 8b 0d 90 01 04 03 4d f4 03 4d f4 03 4d f4 8b 15 90 01 04 8b 35 90 01 04 8a 04 06 88 04 0a 8b 0d 90 01 04 83 c1 01 89 0d 90 00 } //01 00 
		$a_01_1 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 5e 8b e5 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_PA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 05 90 01 04 a3 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 01 04 04 a1 90 01 04 83 c0 04 a3 90 01 04 a1 90 01 04 99 52 50 a1 90 01 04 33 d2 3b 54 24 04 75 90 00 } //01 00 
		$a_00_1 = {8b 16 89 50 08 8b 56 04 89 50 0c 8b 13 89 10 89 58 04 89 42 04 89 03 b0 01 5e 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}