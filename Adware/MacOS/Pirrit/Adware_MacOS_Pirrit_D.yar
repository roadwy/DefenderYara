
rule Adware_MacOS_Pirrit_D{
	meta:
		description = "Adware:MacOS/Pirrit.D,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6b 36 48 7d 5a 7d 4e 3a } //1 k6H}Z}N:
		$a_01_1 = {5b 37 25 71 73 6b 4f 70 } //1 [7%qskOp
		$a_01_2 = {33 41 74 5a 65 6a 6b } //1 3AtZejk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}