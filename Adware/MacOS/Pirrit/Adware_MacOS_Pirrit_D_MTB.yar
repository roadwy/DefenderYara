
rule Adware_MacOS_Pirrit_D_MTB{
	meta:
		description = "Adware:MacOS/Pirrit.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 47 6f 53 65 61 72 63 68 32 32 2e 45 78 74 65 6e 73 69 6f 6e } //01 00 
		$a_00_1 = {4b 36 39 47 35 32 46 57 54 39 } //01 00 
		$a_00_2 = {68 6f 6e 67 73 68 65 6e 67 20 79 61 6e } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}