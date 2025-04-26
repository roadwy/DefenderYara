
rule Trojan_BAT_Disstl_QF_MTB{
	meta:
		description = "Trojan:BAT/Disstl.QF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {48 6f 67 53 74 65 61 6c 65 72 } //HogStealer  1
		$a_80_1 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 31 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 1 & Del  1
		$a_80_2 = {68 61 73 20 62 65 65 6e 20 68 61 73 20 62 65 65 6e 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 48 6f 67 53 74 65 61 6c 65 72 21 } //has been has been infected with HogStealer!  1
		$a_80_3 = {68 74 74 70 73 3a 2f 2f 62 69 74 2e 6c 79 2f 33 39 38 37 56 70 52 } //https://bit.ly/3987VpR  1
		$a_80_4 = {48 6f 67 20 44 65 6c 69 76 65 72 79 20 53 65 72 76 69 63 65 } //Hog Delivery Service  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}