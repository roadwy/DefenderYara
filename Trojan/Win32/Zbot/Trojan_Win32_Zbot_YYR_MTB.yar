
rule Trojan_Win32_Zbot_YYR_MTB{
	meta:
		description = "Trojan:Win32/Zbot.YYR!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06 f3 ab 85 d2 74 0a } //01 00 
		$a_01_1 = {8b 4c 24 04 85 d2 74 69 33 c0 8a 44 24 08 84 c0 75 16 81 fa 00 01 00 00 72 0e 83 3d 80 bb 47 00 00 74 05 e9 c4 a7 00 00 57 8b f9 83 fa 04 72 31 f7 d9 83 e1 03 } //00 00 
	condition:
		any of ($a_*)
 
}