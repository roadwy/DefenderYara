
rule Ransom_AndroidOS_SpySomware_A_MTB{
	meta:
		description = "Ransom:AndroidOS/SpySomware.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 6c 4f 63 4b 65 44 20 46 69 4c 65 3f 2f 6c 6f 63 6b 65 64 2e 7a 69 70 } //01 00 
		$a_00_1 = {58 67 66 67 70 32 72 47 6f 4e 32 50 46 63 31 59 5a 33 7a 31 44 51 3d 3d } //01 00 
		$a_00_2 = {44 37 44 41 38 43 36 46 46 33 33 36 32 34 45 37 35 35 43 41 39 32 38 35 37 35 44 35 35 35 38 32 } //01 00 
		$a_01_3 = {5f 66 75 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}