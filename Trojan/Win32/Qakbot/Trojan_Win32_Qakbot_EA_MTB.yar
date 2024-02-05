
rule Trojan_Win32_Qakbot_EA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 4c 8b 97 c8 00 00 00 8b 87 14 01 00 00 8b 8f 0c 01 00 00 8b 04 82 31 04 8a 8b 8f 38 01 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 03 00 "
		
	strings :
		$a_01_0 = {33 10 89 55 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EA_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a c8 c0 e1 02 8a c4 c0 eb 04 80 e3 03 c0 e0 04 02 d9 8a ca c0 e9 02 80 e1 0f c0 e2 06 02 55 ff 02 c8 8b 45 f0 88 4d 09 88 5d 08 88 55 0a 88 48 ff 8b 4d f8 88 58 fe } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EA_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {47 44 79 5a } //01 00 
		$a_01_1 = {47 48 51 76 42 35 38 68 32 45 } //01 00 
		$a_01_2 = {4d 71 61 65 30 31 69 64 } //01 00 
		$a_01_3 = {53 4e 69 66 43 77 32 34 32 4f 43 44 } //01 00 
		$a_01_4 = {4c 47 76 35 49 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EA_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {2a c1 88 44 35 ec 46 83 fe 04 7c d9 8b 45 ec 8a ec 8a 55 ee 8a c8 83 45 e0 03 8a c4 c0 e1 02 c0 ed 04 80 e5 03 c0 e0 04 02 e9 } //01 00 
		$a_01_1 = {64 66 78 73 67 64 66 68 64 67 66 6a 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EA_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {54 4f 63 53 63 39 38 39 38 4d } //01 00 
		$a_01_2 = {54 52 6f 4d 71 56 43 37 72 } //01 00 
		$a_01_3 = {55 44 4f 79 73 52 } //01 00 
		$a_01_4 = {57 58 62 62 61 32 39 38 4e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EA_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {36 44 75 59 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 36 57 62 79 63 56 4d 59 } //01 00 
		$a_01_3 = {42 51 71 37 58 79 31 77 47 77 } //01 00 
		$a_01_4 = {43 50 66 49 6b 6d 47 } //01 00 
		$a_01_5 = {44 4b 34 65 79 76 49 78 6c 65 } //01 00 
		$a_01_6 = {6a 4e 39 79 2e 64 6c 6c } //01 00 
		$a_01_7 = {42 6d 52 66 48 63 53 6e 4d 39 } //01 00 
		$a_01_8 = {43 62 53 42 42 45 30 76 50 58 59 } //01 00 
		$a_01_9 = {44 55 36 61 36 72 43 57 52 54 38 } //01 00 
		$a_01_10 = {44 46 70 74 64 51 41 64 4e 70 78 } //00 00 
	condition:
		any of ($a_*)
 
}