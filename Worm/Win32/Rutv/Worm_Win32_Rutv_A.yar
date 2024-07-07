
rule Worm_Win32_Rutv_A{
	meta:
		description = "Worm:Win32/Rutv.A,SIGNATURE_TYPE_PEHSTR,29 00 29 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //10 autorun.inf
		$a_01_1 = {53 70 72 65 61 64 54 6f 4e 65 74 77 6f 72 6b } //10 SpreadToNetwork
		$a_01_2 = {4e 65 74 53 68 61 72 65 41 64 64 } //10 NetShareAdd
		$a_01_3 = {4e 65 74 53 68 61 72 65 45 6e 75 6d } //10 NetShareEnum
		$a_01_4 = {68 74 74 70 3a 2f 2f 70 6f 72 6e 6f 73 6c 6f 6e 2e 72 75 2f 69 6e 64 65 78 2e 70 68 70 3f 62 6f 61 72 64 3d } //1 http://pornoslon.ru/index.php?board=
		$a_01_5 = {68 74 74 70 3a 2f 2f 6f 64 6e 6f 6b 6c 61 73 73 6e 69 6b 69 2e 72 75 2f } //1 http://odnoklassniki.ru/
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=41
 
}