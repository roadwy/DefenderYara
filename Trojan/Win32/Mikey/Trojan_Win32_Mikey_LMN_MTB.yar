
rule Trojan_Win32_Mikey_LMN_MTB{
	meta:
		description = "Trojan:Win32/Mikey.LMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 09 00 00 "
		
	strings :
		$a_81_0 = {52 45 53 54 20 49 4e 20 50 49 53 53 2c 20 46 4f 52 45 56 45 52 20 4d 49 53 53 21 } //1 REST IN PISS, FOREVER MISS!
		$a_81_1 = {57 41 52 4e 49 4e 47 3a 20 47 65 74 74 69 6e 67 20 72 69 64 20 6f 66 20 42 6f 6e 7a 69 20 77 69 6c 6c 20 61 6c 73 6f } //2 WARNING: Getting rid of Bonzi will also
		$a_81_2 = {50 72 65 70 61 72 65 20 74 6f 20 6d 65 65 74 20 79 6f 75 72 20 62 69 67 67 65 73 74 20 65 6e 65 6d 79 20 61 67 61 69 6e } //3 Prepare to meet your biggest enemy again
		$a_81_3 = {4f 6b 20 49 27 6c 6c } //4 Ok I'll
		$a_81_4 = {4c 45 54 27 53 20 46 49 47 48 54 21 } //5 LET'S FIGHT!
		$a_81_5 = {72 65 6b 74 2e 65 78 65 } //6 rekt.exe
		$a_81_6 = {45 4e 44 20 4d 59 20 50 41 49 4e 21 } //7 END MY PAIN!
		$a_81_7 = {56 69 6e 65 4d 45 4d 5a } //8 VineMEMZ
		$a_81_8 = {42 6f 6e 7a 69 42 44 59 5f 33 35 2e 45 58 45 } //9 BonziBDY_35.EXE
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*2+(#a_81_2  & 1)*3+(#a_81_3  & 1)*4+(#a_81_4  & 1)*5+(#a_81_5  & 1)*6+(#a_81_6  & 1)*7+(#a_81_7  & 1)*8+(#a_81_8  & 1)*9) >=45
 
}