
rule Trojan_Win32_Qakbot_W{
	meta:
		description = "Trojan:Win32/Qakbot.W,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {2b cb 89 4d fc 90 0a 25 00 90 03 04 04 6a 5a 33 d2 33 d2 6a 5a 8b c1 5e f7 f6 8b 45 90 01 01 8a 04 02 90 02 03 32 04 90 01 01 74 08 41 3b 4d 90 01 01 72 90 00 } //0a 00 
		$a_03_2 = {5f 5e 5b c9 c3 90 0a 2a 00 8b 4d 90 01 01 8b 45 90 01 01 03 ce 03 c1 33 d2 6a 5a 5b f7 f3 8b 45 90 01 01 8a 04 02 32 04 37 46 88 01 3b 75 fc 72 de 8b 45 90 00 } //00 00 
		$a_00_3 = {5d 04 00 00 1f 91 04 80 5c 24 00 00 20 91 04 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}