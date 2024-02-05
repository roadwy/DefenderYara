
rule Backdoor_Linux_HiddenWasp_gen_A{
	meta:
		description = "Backdoor:Linux/HiddenWasp.gen!A!!HiddenWasp.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_81_0 = {6c 69 62 73 65 31 69 6e 75 78 } //01 00 
		$a_81_1 = {49 5f 41 4d 5f 48 49 44 44 45 4e } //01 00 
		$a_81_2 = {48 49 44 45 5f 54 48 49 53 5f 53 48 45 4c 4c } //01 00 
		$a_81_3 = {78 78 64 20 } //01 00 
		$a_81_4 = {69 66 75 70 2d 6c 6f 63 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}