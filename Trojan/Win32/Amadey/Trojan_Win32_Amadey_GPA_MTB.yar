
rule Trojan_Win32_Amadey_GPA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {8a 04 30 32 06 88 45 ff 8d 45 ff 50 c6 45 c0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Amadey_GPA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 4d 66 49 56 5a 4c 43 79 46 33 46 4a 74 73 42 4b 46 31 56 4b 64 71 } //01 00  JMfIVZLCyF3FJtsBKF1VKdq
		$a_01_1 = {65 71 4e 76 51 42 6e 71 4f 78 78 36 } //01 00  eqNvQBnqOxx6
		$a_01_2 = {4b 46 31 46 51 52 6e 6a 66 45 4a 36 4a 33 4b 48 79 75 43 } //01 00  KF1FQRnjfEJ6J3KHyuC
		$a_01_3 = {57 33 31 48 4d 41 34 7a 57 69 4b 32 52 59 65 63 } //00 00  W31HMA4zWiK2RYec
	condition:
		any of ($a_*)
 
}