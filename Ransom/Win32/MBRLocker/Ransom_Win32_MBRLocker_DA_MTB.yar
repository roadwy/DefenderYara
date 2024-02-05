
rule Ransom_Win32_MBRLocker_DA_MTB{
	meta:
		description = "Ransom:Win32/MBRLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {79 6f 75 72 20 77 69 6e 64 6f 77 73 20 77 69 6c 6c 20 64 69 65 20 66 72 6f 6d 20 63 6f 76 69 64 32 31 20 63 6f 72 6f 6e 61 20 76 69 72 75 73 } //01 00 
		$a_81_1 = {63 6f 76 69 64 32 31 20 69 73 20 68 65 72 65 21 20 79 6f 75 72 20 77 69 6e 64 6f 77 73 20 77 69 6c 6c 20 62 65 20 64 65 73 74 72 6f 79 65 64 } //01 00 
		$a_81_2 = {63 6f 72 6f 6e 61 2e 76 62 73 } //01 00 
		$a_81_3 = {50 61 79 6c 6f 61 64 4d 42 52 2e 65 78 65 } //00 00 
	condition:
		any of ($a_*)
 
}