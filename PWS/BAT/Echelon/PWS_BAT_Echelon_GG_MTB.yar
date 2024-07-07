
rule PWS_BAT_Echelon_GG_MTB{
	meta:
		description = "PWS:BAT/Echelon.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_80_0 = {63 72 65 64 69 74 5f 63 61 72 64 } //credit_card  1
		$a_80_1 = {65 63 68 65 6c 6f 6e 2e 74 78 74 } //echelon.txt  1
		$a_80_2 = {70 6f 73 74 } //post  1
		$a_80_3 = {45 63 68 65 6c 6f 6e 5f 44 69 72 } //Echelon_Dir  1
		$a_80_4 = {50 61 73 73 77 6f 72 64 } //Password  1
		$a_80_5 = {63 6f 6f 6b 69 65 73 } //cookies  1
		$a_80_6 = {47 72 61 62 62 65 72 } //Grabber  1
		$a_80_7 = {4d 6f 6e 65 72 6f } //Monero  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=7
 
}
rule PWS_BAT_Echelon_GG_MTB_2{
	meta:
		description = "PWS:BAT/Echelon.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 "
		
	strings :
		$a_02_0 = {16 fe 01 0c 90 0a 78 00 14 fe 90 02 06 73 90 02 06 6f 90 02 06 00 00 7e 90 02 06 72 90 02 06 7e 90 02 06 28 90 02 06 28 90 02 06 0b 07 2c 90 02 02 00 7e 90 02 06 72 90 02 06 7e 90 02 06 28 90 02 06 28 90 02 06 7e 90 02 06 6f 90 00 } //10
		$a_80_1 = {47 65 74 53 74 65 61 6c 65 72 } //GetStealer  1
		$a_80_2 = {45 63 68 65 6c 6f 6e 5f 44 69 72 } //Echelon_Dir  1
		$a_80_3 = {47 72 61 62 62 65 72 } //Grabber  1
		$a_80_4 = {70 61 73 73 77 6f 72 64 7a 69 70 } //passwordzip  1
		$a_80_5 = {4d 6f 6e 65 72 6f } //Monero  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=14
 
}