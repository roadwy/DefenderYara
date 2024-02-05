
rule Trojan_Win32_Qakbot_EC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8b c2 0f af c2 03 f0 89 b1 9c 00 00 00 8b 81 94 00 00 00 83 f0 2f 0b f8 42 89 79 24 3b 51 38 76 df } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 08 00 "
		
	strings :
		$a_01_0 = {8b 82 9c 00 00 00 33 c5 33 42 30 0f af 82 d4 00 00 00 89 82 d4 00 00 00 8b 82 a8 00 00 00 83 c1 02 23 42 48 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {29 34 e4 01 3c e4 50 31 04 e4 58 21 45 fc 6a 00 89 2c e4 29 ed 31 c5 89 e9 5d 89 55 f4 33 55 f4 31 c2 } //02 00 
		$a_01_1 = {6a 00 89 0c e4 ff 75 fc 59 01 f9 89 4d fc 59 c1 e7 04 49 75 eb } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EC_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 75 63 4b 4a 36 36 30 } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_2 = {4f 65 4b 4c 72 39 4c } //01 00 
		$a_01_3 = {50 49 6c 70 70 6e 33 35 69 32 } //01 00 
		$a_01_4 = {57 68 7a 78 71 59 30 4a 72 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EC_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_1 = {30 7a 33 44 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 50 59 79 6c 49 39 30 } //01 00 
		$a_01_3 = {42 4a 39 76 59 54 49 5a } //01 00 
		$a_01_4 = {43 38 36 37 7a 4f 53 6f } //01 00 
		$a_01_5 = {44 6b 71 70 79 45 6a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EC_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 73 6f 6c 76 69 6e 67 20 68 6f 73 74 6e 61 6d 65 } //01 00 
		$a_01_1 = {67 65 74 68 6f 73 74 62 79 61 64 64 72 } //01 00 
		$a_01_2 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //01 00 
		$a_01_3 = {32 32 79 6c 6b 75 38 79 68 30 34 39 79 75 30 33 34 68 6b 6f 66 77 34 32 68 34 72 79 6a 30 32 67 39 34 30 67 39 76 72 67 68 77 30 38 } //01 00 
		$a_01_4 = {70 65 47 44 74 61 4b 48 78 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_EC_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 53 49 6b 78 6c 65 42 50 51 6c 63 51 53 7a 47 4d 4e 61 6f 63 5a 6c 42 4e 44 55 } //01 00 
		$a_01_1 = {52 6a 55 66 76 6d 54 70 61 65 73 42 43 61 45 48 72 6b 61 6b 42 44 5a 43 68 7a 56 6f } //01 00 
		$a_01_2 = {61 4c 68 65 51 63 6d 4d 75 46 44 68 71 54 } //01 00 
		$a_01_3 = {72 72 66 50 67 4a 4b 67 63 71 42 65 } //01 00 
		$a_01_4 = {46 79 77 47 47 6b 43 79 6d 56 71 41 46 61 73 66 42 76 64 48 4c 67 50 41 54 78 7a 77 } //01 00 
		$a_01_5 = {76 70 49 4d 73 59 4b 63 66 6c 43 6f 68 43 73 42 65 4e 4d 59 71 52 41 44 62 61 48 } //00 00 
	condition:
		any of ($a_*)
 
}