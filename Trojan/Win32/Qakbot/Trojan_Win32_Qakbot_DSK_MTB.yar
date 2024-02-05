
rule Trojan_Win32_Qakbot_DSK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 44 24 50 8b 4c 24 60 89 ca 81 c2 b3 d7 b3 9a 89 54 24 04 99 8b 74 24 04 f7 fe 89 d0 8b 7c 24 14 8a 1c 17 8b 74 24 44 88 1e 8a 5c 24 4f 88 1c 17 } //02 00 
		$a_01_1 = {8b 44 24 18 0d c6 1c a1 4e 01 f2 88 d7 0f b6 d7 8b 74 24 20 89 74 24 74 89 44 24 70 8a 7c 24 6b 80 c7 a0 8b 44 24 14 8a 04 10 30 d8 88 7c 24 6b 8b 54 24 28 88 04 3a } //00 00 
	condition:
		any of ($a_*)
 
}