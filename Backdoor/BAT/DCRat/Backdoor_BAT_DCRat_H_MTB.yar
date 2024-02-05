
rule Backdoor_BAT_DCRat_H_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {77 ff b7 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 30 01 00 00 0c 01 00 00 1e 05 00 00 85 06 } //01 00 
		$a_01_1 = {55 4e 43 4f 4d 50 52 45 53 53 45 44 5f 45 4e 44 } //01 00 
		$a_01_2 = {55 4e 43 4f 4e 44 49 54 49 4f 4e 41 4c 5f 4d 41 54 43 48 4c 45 4e } //00 00 
	condition:
		any of ($a_*)
 
}