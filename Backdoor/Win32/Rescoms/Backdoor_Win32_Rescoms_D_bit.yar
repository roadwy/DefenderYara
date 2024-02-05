
rule Backdoor_Win32_Rescoms_D_bit{
	meta:
		description = "Backdoor:Win32/Rescoms.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 55 fc 8a 54 1a ff 8b 4d f8 8a 4c 19 ff 32 d1 88 54 18 ff 43 4e 75 e1 } //01 00 
		$a_01_1 = {8b 55 fc 8a 1a 8b d3 c1 e2 04 33 c9 8a cb c1 e9 04 0a d1 88 10 } //01 00 
		$a_03_2 = {73 76 63 68 6f 73 74 2e 65 78 65 90 02 10 53 74 69 6b 79 4e 6f 74 2e 65 78 65 90 02 10 53 79 6e 63 48 6f 73 74 2e 65 78 65 90 02 10 73 79 73 74 72 61 79 2e 65 78 65 90 02 10 74 61 73 6b 65 6e 67 2e 65 78 65 90 02 10 74 61 73 6b 6c 69 73 74 2e 65 78 65 90 00 } //01 00 
		$a_01_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}