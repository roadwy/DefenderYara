
rule Ransom_Win32_SivoCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/SivoCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 73 00 69 00 76 00 6f 00 } //01 00 
		$a_01_1 = {5c 73 69 76 6f 2e 70 64 62 } //01 00 
		$a_01_2 = {53 69 76 6f 2d 52 45 41 44 4d 45 2e 74 78 74 } //01 00 
		$a_01_3 = {45 6e 63 72 79 70 74 65 64 45 78 74 } //01 00 
		$a_01_4 = {77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 63 61 6c 6c 20 63 72 65 61 74 65 20 56 6f 6c 75 6d 65 3d } //00 00 
		$a_00_5 = {5d 04 00 } //00 0a 
	condition:
		any of ($a_*)
 
}