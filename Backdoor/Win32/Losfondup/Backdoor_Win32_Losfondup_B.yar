
rule Backdoor_Win32_Losfondup_B{
	meta:
		description = "Backdoor:Win32/Losfondup.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f af de 81 fb 38 04 00 00 7c b1 81 fb 18 f6 00 00 7f a9 } //01 00 
		$a_01_1 = {72 1f 6a 00 6a 00 6a 00 6a 00 6a 00 56 57 53 6a 00 68 00 00 00 02 8d 44 24 30 50 ff 54 24 44 eb 18 } //01 00 
		$a_01_2 = {c6 02 e9 2b f0 2b f3 83 ee 05 42 89 32 } //01 00 
		$a_03_3 = {bf 28 00 00 00 33 f6 6a 05 e8 90 01 04 3b ee 0f 84 64 03 00 00 8b c7 e8 90 01 04 83 f8 28 0f 87 44 03 00 00 ff 24 85 90 00 } //01 00 
		$a_01_4 = {c7 45 fc 9a 02 00 00 6a 00 6a 04 8d 45 fc 50 53 e8 } //01 00 
		$a_01_5 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 73 20 22 4c 4f 43 41 4c 20 53 45 52 56 6c 43 45 22 20 2f 61 64 64 } //01 00 
	condition:
		any of ($a_*)
 
}