
rule Backdoor_Win32_Sereki_gen_B{
	meta:
		description = "Backdoor:Win32/Sereki.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0e 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 65 6c 66 6b 00 } //01 00 
		$a_01_1 = {72 65 62 6f 6f 74 00 } //01 00 
		$a_01_2 = {63 6f 6d 6d 61 6e 64 00 } //01 00 
		$a_00_3 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //0a 00 
		$a_03_4 = {32 0c 10 48 88 4c 24 13 79 f6 8d 4c 24 13 6a 01 51 53 ff 15 90 01 04 83 c4 0c 46 3b f5 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}