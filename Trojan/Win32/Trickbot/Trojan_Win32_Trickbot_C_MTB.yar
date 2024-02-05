
rule Trojan_Win32_Trickbot_C_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 ef 01 89 5d e0 01 fb 8b 7d e0 0f af fb 83 e7 01 83 ff 00 0f 94 c3 80 e3 01 88 5d ee } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_C_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.C!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 } //01 00 
		$a_01_1 = {33 00 34 00 32 00 31 00 4b 04 46 04 45 04 18 04 42 04 3d 04 30 04 2e 00 65 00 78 00 65 00 00 00 } //01 00 
		$a_01_2 = {4d 63 56 6a 64 30 6c 7c 65 50 78 43 50 67 2a 68 79 54 49 40 48 63 38 } //01 00 
		$a_01_3 = {5a 7b 6f 38 6a 7b 49 58 58 63 30 63 40 33 71 } //01 00 
		$a_01_4 = {50 6c 61 79 65 72 2e 62 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}