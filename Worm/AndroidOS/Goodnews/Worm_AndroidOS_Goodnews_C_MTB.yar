
rule Worm_AndroidOS_Goodnews_C_MTB{
	meta:
		description = "Worm:AndroidOS/Goodnews.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {47 65 74 74 69 6e 67 20 64 65 74 61 69 6c 73 2e 2e 2e 2e } //01 00  Getting details....
		$a_00_1 = {43 6c 69 63 6b 20 6f 6e 20 41 64 20 61 6e 64 20 69 6e 73 74 61 6c 6c 20 61 70 70 20 74 6f 20 43 6f 6e 74 69 6e 75 65 21 21 } //01 00  Click on Ad and install app to Continue!!
		$a_00_2 = {50 6c 65 61 73 65 20 43 6c 69 63 6b 20 6f 6e 20 41 44 20 74 6f 20 61 6e 64 20 49 6e 73 74 61 6c 6c 20 61 70 70 20 74 6f 20 63 6f 6e 74 69 6e 75 65 } //01 00  Please Click on AD to and Install app to continue
		$a_00_3 = {2f 2f 74 69 6e 79 2e 63 63 2f 43 4f 56 49 44 2d 56 41 43 43 49 4e 45 } //00 00  //tiny.cc/COVID-VACCINE
		$a_00_4 = {5d 04 00 } //00 90 
	condition:
		any of ($a_*)
 
}