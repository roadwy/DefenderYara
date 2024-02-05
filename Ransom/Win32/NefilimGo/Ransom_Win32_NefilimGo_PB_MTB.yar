
rule Ransom_Win32_NefilimGo_PB_MTB{
	meta:
		description = "Ransom:Win32/NefilimGo.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 4c 45 41 4b 53 } //01 00 
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 } //01 00 
		$a_01_2 = {4c 45 41 4b 53 21 21 21 44 41 4e 47 45 52 2e 74 78 74 } //01 00 
		$a_01_3 = {2e 49 73 45 6e 63 72 79 70 74 65 64 50 45 4d 42 6c 6f 63 6b } //01 00 
		$a_00_4 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //00 00 
	condition:
		any of ($a_*)
 
}