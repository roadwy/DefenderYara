
rule Trojan_BAT_Redline_UY_MTB{
	meta:
		description = "Trojan:BAT/Redline.UY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {32 31 32 2e 31 39 32 2e 33 31 2e 37 33 } //212.192.31.73  1
		$a_80_1 = {69 6e 63 6f 6e 69 69 69 6f 63 6f 63 6f 77 67 2e 72 75 } //inconiiiococowg.ru  1
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_80_3 = {47 00 56 00 6b 00 4f 00 43 00 30 00 34 00 4f 00 44 00 67 00 30 00 4c 00 57 00 59 00 30 00 4e 00 7a 00 59 00 31 00 4d 00 44 00 6b 00 35 00 } //G  1
		$a_80_4 = {4e 44 63 30 4e 69 30 35 59 32 4d 35 4c 54 68 68 5a 6a 4d 32 4d 54 4e 6a 59 54 63 78 4d 58 30 73 49 45 4e 31 62 } //NDc0Ni05Y2M5LThhZjM2MTNjYTcxMX0sIEN1b  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}