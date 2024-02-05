
rule Backdoor_Win32_Adialer_B{
	meta:
		description = "Backdoor:Win32/Adialer.B,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd7 00 ffffffd2 00 05 00 00 64 00 "
		
	strings :
		$a_02_0 = {ff d6 6a 00 ff 75 10 53 ff 15 90 01 04 53 ff d6 53 8b f0 e8 2e 00 00 00 8b 45 0c 59 89 38 90 00 } //64 00 
		$a_00_1 = {8d 87 00 00 40 00 8d 8e 98 00 00 00 89 46 14 8d 46 18 89 4e 0c 89 7e 10 89 46 08 33 ed b9 f1 00 00 00 33 d2 83 fd 10 0f 9d c2 4a } //05 00 
		$a_00_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //05 00 
		$a_00_3 = {45 72 72 65 75 72 20 74 68 65 20 41 70 70 6c 20 42 75 66 66 65 72 } //05 00 
		$a_00_4 = {45 72 72 65 75 72 20 64 65 20 6c 65 63 74 75 72 65 20 64 75 20 66 69 63 68 69 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}