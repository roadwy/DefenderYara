
rule Adware_MacOS_Pirrit_E{
	meta:
		description = "Adware:MacOS/Pirrit.E,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 65 56 6f 42 4c 6e 6c } //01 00 
		$a_01_1 = {7b 45 68 2e 63 31 64 } //01 00 
		$a_01_2 = {4b 42 35 65 4c 54 5c 54 } //00 00 
	condition:
		any of ($a_*)
 
}