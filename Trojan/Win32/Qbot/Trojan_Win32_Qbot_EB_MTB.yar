
rule Trojan_Win32_Qbot_EB_MTB{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {33 d2 03 04 24 13 54 24 04 83 c4 08 } //02 00 
		$a_01_1 = {29 04 24 19 54 24 04 58 5a 2b d8 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {89 45 a4 8b 45 d8 8b 55 a8 01 10 8b 45 c4 03 45 a4 89 45 a0 6a 00 e8 90 01 04 03 45 a0 40 8b 55 d8 33 02 89 45 a0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qbot_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 00 49 00 61 00 4b 00 48 00 48 00 64 00 49 00 61 00 65 00 79 00 7a 00 56 00 79 00 4d 00 70 00 4b 00 4b 00 64 00 44 00 6a 00 57 00 4a 00 50 00 4d 00 54 00 68 00 4e 00 4a 00 6a 00 6d 00 56 00 69 00 } //01 00 
		$a_01_1 = {69 00 62 00 64 00 57 00 56 00 6c 00 5a 00 42 00 43 00 6d 00 48 00 50 00 4c 00 61 00 6c 00 44 00 66 00 47 00 70 00 50 00 47 00 6d 00 46 00 57 00 50 00 76 00 63 00 65 00 65 00 54 00 43 00 54 00 59 00 } //01 00 
		$a_01_2 = {6e 00 66 00 4f 00 54 00 4c 00 6c 00 53 00 66 00 73 00 4a 00 } //01 00 
		$a_01_3 = {7a 00 72 00 7a 00 4b 00 76 00 6b 00 55 00 62 00 48 00 65 00 79 00 6e 00 54 00 54 00 4d 00 74 00 47 00 } //01 00 
		$a_01_4 = {4b 00 50 00 62 00 6f 00 56 00 6b 00 76 00 } //00 00 
	condition:
		any of ($a_*)
 
}