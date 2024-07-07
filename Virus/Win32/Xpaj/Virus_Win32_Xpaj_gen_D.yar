
rule Virus_Win32_Xpaj_gen_D{
	meta:
		description = "Virus:Win32/Xpaj.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 08 00 00 "
		
	strings :
		$a_00_0 = {68 41 56 45 52 68 46 55 43 4b } //4 hAVERhFUCK
		$a_03_1 = {81 7e 03 70 3a 2f 2f 0f 84 0d 00 00 00 81 7e 03 50 3a 2f 2f 0f 85 90 01 02 00 00 90 00 } //4
		$a_00_2 = {c7 47 04 69 63 65 5c } //4
		$a_00_3 = {c7 07 63 3a 5c 00 6a 00 6a 00 6a 00 6a 00 } //4
		$a_00_4 = {3a 2f 2f 6f 70 65 6e 64 61 73 68 65 6c 6c 2e 63 6f 6d } //1 ://opendashell.com
		$a_00_5 = {3a 2f 2f 63 68 6f 70 63 68 6f 70 63 68 75 70 2e 63 6f 6d } //1 ://chopchopchup.com
		$a_00_6 = {3a 2f 2f 67 75 73 74 6f 62 6c 61 2e 63 6f 6d } //1 ://gustobla.com
		$a_00_7 = {3a 2f 2f 73 61 6c 74 6f 64 65 6d 6f 72 74 61 6c 6c 65 78 2e 63 6f 6d } //1 ://saltodemortallex.com
	condition:
		((#a_00_0  & 1)*4+(#a_03_1  & 1)*4+(#a_00_2  & 1)*4+(#a_00_3  & 1)*4+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=12
 
}