
rule Trojan_Win32_Qakbot_EM_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b cb 83 c6 04 0b cf 0b 4c 24 30 0b d1 8b cd 89 90 a8 00 00 00 2b 48 0c 69 c9 4c 03 00 00 3b f1 72 de } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_03_0 = {03 d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {55 8b ec 83 ec 08 89 4d fc 8b 45 fc 89 45 f8 6b 45 08 18 8b 4d f8 03 01 8b e5 5d } //01 00 
		$a_01_1 = {64 65 73 6b 74 6f 70 2e 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EM_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {6a 50 55 4d 4f 4f 55 69 45 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 6d 58 58 36 69 31 57 78 68 } //01 00 
		$a_01_3 = {44 33 67 34 67 43 68 32 } //01 00 
		$a_01_4 = {4a 6b 44 70 7a 44 4f 52 56 55 } //01 00 
		$a_01_5 = {43 53 4e 5a 34 7a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EM_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 03 00 "
		
	strings :
		$a_81_0 = {5a 48 78 62 45 54 6f 70 75 4f 49 } //03 00 
		$a_81_1 = {67 55 6d 61 6d 58 50 } //03 00 
		$a_81_2 = {6a 4b 75 45 6b 68 62 4d 6b 4d 68 59 4b 47 } //03 00 
		$a_81_3 = {53 63 72 69 70 74 43 50 74 6f 58 } //03 00 
		$a_81_4 = {53 63 72 69 70 74 41 70 70 6c 79 4c 6f 67 69 63 61 6c 57 69 64 74 68 } //03 00 
		$a_81_5 = {43 6c 6f 73 65 45 6e 68 4d 65 74 61 46 69 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}