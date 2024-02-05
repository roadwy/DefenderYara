
rule Backdoor_Win64_DCRat_GP_MTB{
	meta:
		description = "Backdoor:Win64/DCRat.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0f b6 14 03 0f b6 4c 05 00 30 d1 88 0c 03 88 54 05 00 48 8d 48 01 48 89 c8 49 39 cf 75 e2 } //01 00 
		$a_01_1 = {70 65 73 74 69 6c 65 6e 63 65 2e 70 64 62 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 4d 75 74 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}