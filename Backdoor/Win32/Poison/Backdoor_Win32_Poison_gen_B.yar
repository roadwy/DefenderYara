
rule Backdoor_Win32_Poison_gen_B{
	meta:
		description = "Backdoor:Win32/Poison.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 00 00 eb a8 81 bd 30 fa ff ff 63 6b 73 3d 75 13 d7 85 30 fa ff ff 74 74 70 3d c6 86 ef 0a 00 } //01 00 
		$a_00_1 = {e8 07 00 00 00 57 73 32 5f 33 32 00 58 50 ff 96 9d 00 00 00 89 86 c3 0a 00 00 e8 3a 00 00 00 e1 } //01 00 
		$a_00_2 = {6c 6c 65 64 20 43 6f 6d 70 6f 6e 65 6e 74 73 5c fa 0a 05 00 6b 69 6c 65 72 90 01 0d 00 09 31 32 } //01 00 
		$a_00_3 = {00 00 c1 02 04 00 ff ff ff ff 45 01 05 00 61 64 6d 69 6e fb 03 05 00 63 63 78 63 73 fa 03 01 00 } //01 00 
		$a_01_4 = {4f 4e 6e 45 43 54 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 } //00 00 
	condition:
		any of ($a_*)
 
}