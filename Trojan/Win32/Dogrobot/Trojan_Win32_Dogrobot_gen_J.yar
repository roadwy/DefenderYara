
rule Trojan_Win32_Dogrobot_gen_J{
	meta:
		description = "Trojan:Win32/Dogrobot.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 e9 8b 45 14 8b 5d 08 2b c3 83 e8 05 89 45 f1 8d 45 f0 6a 05 } //02 00 
		$a_01_1 = {8a 0c 32 8a c2 2c 21 8b fe d0 e0 02 c8 33 c0 88 0c 32 83 c9 ff 42 f2 ae f7 d1 49 3b d1 72 e1 } //01 00 
		$a_00_2 = {81 e5 00 f0 00 00 81 fd 00 30 00 00 75 31 8b 5c 24 10 8b 6c 24 28 43 25 ff 0f 00 00 89 5c 24 10 8b 19 03 c3 8b 1c 30 2b 5d 1c 8b 6c 24 2c 3b dd 75 09 66 81 7c 30 fe c7 05 74 15 } //00 00 
	condition:
		any of ($a_*)
 
}