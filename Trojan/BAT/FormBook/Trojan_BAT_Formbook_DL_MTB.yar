
rule Trojan_BAT_Formbook_DL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 66 30 36 35 36 34 30 65 2d 39 37 65 32 2d 34 31 37 39 2d 61 62 64 64 2d 35 39 62 33 61 32 34 62 64 30 62 32 } //1 $f065640e-97e2-4179-abdd-59b3a24bd0b2
		$a_81_1 = {50 72 6f 67 72 61 6d 6d 69 6e 67 20 50 72 6f 6a 65 63 74 } //1 Programming Project
		$a_81_2 = {46 69 6c 65 20 6d 69 73 73 69 6e 67 21 21 21 } //1 File missing!!!
		$a_81_3 = {40 74 65 6c 65 70 68 6f 6e 65 } //1 @telephone
		$a_81_4 = {43 79 70 72 75 73 } //1 Cyprus
		$a_81_5 = {75 70 5f 74 6f 5f 31 30 5f 64 6f 6d 61 69 6e 73 } //1 up_to_10_domains
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}