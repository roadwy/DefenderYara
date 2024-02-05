
rule Backdoor_Win32_Stokief_A{
	meta:
		description = "Backdoor:Win32/Stokief.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7f 43 8b 45 9c 03 85 74 ff ff ff 80 38 23 75 11 8d 45 f8 03 85 74 ff ff ff 83 c0 80 c6 00 00 } //02 00 
		$a_01_1 = {77 6d 5f 68 6f 6f 6b 73 2e 64 6c 6c 00 6c 6f 67 6d 65 73 73 61 67 65 73 2e 64 6c 6c 00 75 70 66 74 70 00 76 6e 63 69 6e 69 } //01 00 
		$a_01_2 = {2f 70 75 62 6c 69 63 5f 68 74 6d 6c 2f 6b 6c 6f 67 2f 25 73 2f 00 6b 65 79 6c 6f 67 2e 6c 6f 67 } //01 00 
		$a_01_3 = {69 6e 66 65 63 74 61 6e 64 6f 20 64 69 73 63 6f 20 6c 6f 63 61 6c 2e 2e 2e } //00 00 
	condition:
		any of ($a_*)
 
}