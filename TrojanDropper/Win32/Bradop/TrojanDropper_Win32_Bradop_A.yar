
rule TrojanDropper_Win32_Bradop_A{
	meta:
		description = "TrojanDropper:Win32/Bradop.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {83 c7 06 83 ff 08 7c 55 83 ef 08 8d 45 e8 ba 28 1c } //01 00 
		$a_03_1 = {2e 63 70 6c 90 01 0c 53 68 65 6c 6c 33 32 2e 64 6c 6c 2c 43 6f 6e 74 72 6f 6c 5f 52 75 6e 44 4c 4c 20 22 90 00 } //01 00 
		$a_01_2 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 4f 50 45 4e 00 } //01 00 
		$a_01_3 = {4a 4c 66 49 6d 6f 58 33 41 4b 39 62 4b 63 79 58 } //00 00 
	condition:
		any of ($a_*)
 
}