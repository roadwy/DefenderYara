
rule Ransom_Win32_Criakl_D{
	meta:
		description = "Ransom:Win32/Criakl.D,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7d 7b 45 4e 43 52 59 50 54 45 4e 44 45 44 7d 00 } //01 00 
		$a_01_1 = {7b 42 4c 4f 43 4b 53 53 54 41 52 54 7d 00 } //01 00 
		$a_01_2 = {2e 72 61 6e 64 6f 6d 6e 61 6d 65 2d 00 } //01 00 
		$a_01_3 = {7b 42 4c 4f 43 4b 53 45 4e 44 7d 00 } //02 00 
		$a_03_4 = {66 64 62 3a 66 62 66 3a 6d 61 78 3a 6d 33 64 3a 90 03 07 0c 64 62 66 3a 6c 64 66 6c 64 66 3a 6b 65 79 73 74 6f 72 65 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}