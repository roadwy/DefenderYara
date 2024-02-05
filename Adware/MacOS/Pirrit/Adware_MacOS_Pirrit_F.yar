
rule Adware_MacOS_Pirrit_F{
	meta:
		description = "Adware:MacOS/Pirrit.F,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 52 4f 46 6b 4d 43 4d 31 } //01 00 
		$a_01_1 = {6d 4b 32 4c 32 4e 39 } //01 00 
		$a_01_2 = {43 2a 6c 30 73 2b 3d } //00 00 
	condition:
		any of ($a_*)
 
}