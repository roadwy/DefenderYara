
rule PWS_BAT_Browsstl_GG_MTB{
	meta:
		description = "PWS:BAT/Browsstl.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0c 00 00 "
		
	strings :
		$a_80_0 = {42 72 6f 77 73 65 72 73 } //Browsers  1
		$a_80_1 = {43 68 72 6f 6d 69 75 6d } //Chromium  1
		$a_80_2 = {46 69 72 65 66 6f 78 } //Firefox  1
		$a_80_3 = {43 6f 6f 6b 69 65 73 } //Cookies  1
		$a_80_4 = {43 72 65 64 65 6e 74 69 61 6c 73 } //Credentials  1
		$a_80_5 = {43 72 65 64 69 74 5f 43 61 72 64 73 } //Credit_Cards  1
		$a_80_6 = {43 72 65 64 69 74 5f 43 61 72 64 73 5f 44 61 74 61 } //Credit_Cards_Data  1
		$a_80_7 = {41 75 74 6f 66 69 6c 6c } //Autofill  1
		$a_80_8 = {53 71 6c 69 74 65 } //Sqlite  1
		$a_80_9 = {42 43 72 79 70 74 } //BCrypt  1
		$a_80_10 = {44 65 62 75 67 67 65 72 } //Debugger  1
		$a_80_11 = {67 65 74 5f 49 73 41 6c 69 76 65 } //get_IsAlive  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=11
 
}