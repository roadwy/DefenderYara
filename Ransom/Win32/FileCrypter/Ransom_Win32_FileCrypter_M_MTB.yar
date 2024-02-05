
rule Ransom_Win32_FileCrypter_M_MTB{
	meta:
		description = "Ransom:Win32/FileCrypter.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } //01 00 
		$a_81_1 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //01 00 
		$a_81_2 = {75 6e 72 65 61 63 68 61 62 6c 65 75 73 65 72 65 6e 76 2e 64 6c 6c } //01 00 
		$a_81_3 = {46 50 5f 4e 4f 5f 48 4f 53 54 5f 43 48 45 43 4b } //01 00 
		$a_81_4 = {6c 6f 63 6b 66 69 6c 65 } //01 00 
		$a_81_5 = {55 6e 6c 6f 63 6b 46 69 6c 65 } //01 00 
		$a_81_6 = {2e 53 4e 50 44 52 47 4e } //00 00 
	condition:
		any of ($a_*)
 
}