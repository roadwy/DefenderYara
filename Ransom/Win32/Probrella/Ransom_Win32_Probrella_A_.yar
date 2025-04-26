
rule Ransom_Win32_Probrella_A_{
	meta:
		description = "Ransom:Win32/Probrella.A!!Probrella.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,07 00 07 00 0a 00 00 "
		
	strings :
		$a_80_0 = {73 6d 74 70 2e 6e 6f 70 72 6f 62 6c 65 6d 62 72 6f 2e 63 6f 6d 00 } //smtp.noproblembro.com  1
		$a_80_1 = {4c 6f 63 6b 65 64 20 2d 20 00 } //Locked -   1
		$a_80_2 = {50 43 3a 00 } //PC:  1
		$a_80_3 = {50 61 73 73 77 6f 72 64 3a 00 } //Password:  1
		$a_80_4 = {64 65 63 72 79 70 74 6f 72 32 30 31 33 40 67 6d 61 69 6c 2e 63 6f 6d 2c } //decryptor2013@gmail.com,  1
		$a_80_5 = {2d 2d 2d 54 65 63 68 2d 42 65 67 69 6e 2d 2d 2d 00 } //---Tech-Begin---  1
		$a_80_6 = {55 6d 62 72 65 6c 6c 61 20 43 6f 72 70 6f 72 61 74 69 6f 6e 00 } //Umbrella Corporation  1
		$a_80_7 = {4f 75 72 20 57 6f 72 6b 20 49 73 20 59 6f 75 72 20 4c 69 66 65 00 } //Our Work Is Your Life  1
		$a_80_8 = {44 65 6c 65 74 65 20 53 68 61 64 6f 77 73 20 2f 41 6c 6c 20 2f 51 75 69 65 74 00 } //Delete Shadows /All /Quiet  1
		$a_80_9 = {2e 6c 6f 63 6b 65 64 00 } //.locked  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=7
 
}