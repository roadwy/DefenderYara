
rule Adware_MacOS_Pirrit_D{
	meta:
		description = "Adware:MacOS/Pirrit.D,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 36 48 7d 5a 7d 4e 3a } //01 00  k6H}Z}N:
		$a_01_1 = {5b 37 25 71 73 6b 4f 70 } //01 00  [7%qskOp
		$a_01_2 = {33 41 74 5a 65 6a 6b } //00 00  3AtZejk
	condition:
		any of ($a_*)
 
}