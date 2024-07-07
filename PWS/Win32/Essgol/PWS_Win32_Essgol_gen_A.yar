
rule PWS_Win32_Essgol_gen_A{
	meta:
		description = "PWS:Win32/Essgol.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0c 00 0d 00 00 "
		
	strings :
		$a_01_0 = {41 63 63 6f 75 6e 74 49 44 3d 25 73 26 50 61 73 73 50 68 72 61 73 65 3d 25 73 26 41 6d 6f 75 6e 74 3d 25 73 26 45 6d 61 69 6c 3d 25 73 } //4 AccountID=%s&PassPhrase=%s&Amount=%s&Email=%s
		$a_00_1 = {63 6c 6f 73 65 65 76 65 6e 74 65 67 6f 6c 64 31 } //2 closeeventegold1
		$a_00_2 = {43 4c 53 49 44 5c 7b 39 32 36 31 37 39 33 34 } //2 CLSID\{92617934
		$a_01_3 = {41 63 63 6f 75 6e 74 49 44 3d } //1 AccountID=
		$a_01_4 = {50 61 73 73 50 68 72 61 73 65 3d } //1 PassPhrase=
		$a_00_5 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d 2f } //1 https://www.e-gold.com/
		$a_00_6 = {61 63 63 74 2f 61 63 63 74 2e 61 73 70 } //1 acct/acct.asp
		$a_00_7 = {61 63 63 74 2f 61 63 63 6f 75 6e 74 69 6e 66 6f 2e 61 73 70 } //1 acct/accountinfo.asp
		$a_00_8 = {61 63 63 74 2f 62 61 6c 61 6e 63 65 2e 61 73 70 } //1 acct/balance.asp
		$a_01_9 = {55 73 65 72 2d 41 67 65 6e 74 3a } //1 User-Agent:
		$a_01_10 = {41 63 63 65 70 74 2d 45 6e 63 6f 64 69 6e 67 3a } //1 Accept-Encoding:
		$a_01_11 = {3d 44 69 73 61 62 6c 65 64 } //1 =Disabled
		$a_01_12 = {53 65 63 75 72 69 74 79 4c 65 76 65 6c } //1 SecurityLevel
	condition:
		((#a_01_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=12
 
}