
rule Trojan_Win32_Qakbot_EB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {2b 13 2b 17 8b 45 f8 8a 14 10 8b 45 08 32 14 08 8b 45 fc 88 14 08 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b d8 8b 45 d8 8b 00 03 45 a8 03 d8 } //03 00 
		$a_01_1 = {03 d8 8b 45 d8 33 18 89 5d a0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {8b d3 03 f8 8b 86 48 01 00 00 8b cf d3 ea 8b 4e 1c 8a 40 90 01 01 34 90 01 01 22 d0 8b 86 34 01 00 00 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_03_0 = {89 02 6a 00 e8 90 01 04 8b d8 03 1d 90 01 04 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 03 d8 a1 90 01 04 33 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 58 50 42 4c 47 32 47 79 } //01 00 
		$a_01_1 = {45 7a 4d 4e 62 51 4c } //01 00 
		$a_01_2 = {48 6e 67 57 4d 30 78 } //01 00 
		$a_01_3 = {4e 73 72 36 34 30 59 } //01 00 
		$a_01_4 = {52 4f 55 4f 38 30 39 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 58 66 50 38 33 36 71 36 } //01 00 
		$a_01_1 = {44 72 61 77 54 68 65 6d 65 49 63 6f 6e } //01 00 
		$a_01_2 = {47 72 58 70 34 30 } //01 00 
		$a_01_3 = {53 6b 6a 39 32 57 } //01 00 
		$a_01_4 = {57 49 75 64 4b 33 39 38 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 02 6a 00 e8 90 01 04 8b 1d 90 01 04 03 1d 90 01 04 03 1d 90 01 04 4b 2b d8 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 03 d8 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EB_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 6f 59 4c 6f 41 55 6c 58 7a 4f 6e 62 43 64 4b 65 73 77 68 4a 61 70 } //01 00 
		$a_01_1 = {67 5a 4a 58 77 59 47 4a 77 44 4d 67 50 6c 68 4c 65 63 70 49 76 71 70 } //01 00 
		$a_01_2 = {4a 58 53 51 49 50 47 4b 71 63 6c 68 44 50 4f 4a 61 6b 6a } //01 00 
		$a_01_3 = {48 5a 31 30 4b 49 31 38 4e 5f 4b 55 49 54 76 } //01 00 
		$a_01_4 = {48 5a 32 33 72 65 6d 6f 76 65 41 63 63 65 6c 65 72 61 74 6f 72 4d 61 72 6b 65 72 52 4b 37 51 53 74 72 69 6e 67 } //01 00 
		$a_01_5 = {48 5a 35 4b 49 31 38 4e 76 } //01 00 
		$a_01_6 = {48 5a 35 6b 69 31 38 6e 50 4b 63 } //00 00 
	condition:
		any of ($a_*)
 
}