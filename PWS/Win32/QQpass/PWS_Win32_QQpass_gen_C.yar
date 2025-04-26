
rule PWS_Win32_QQpass_gen_C{
	meta:
		description = "PWS:Win32/QQpass.gen!C,SIGNATURE_TYPE_PEHSTR,1f 00 1f 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 50 61 67 65 00 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e } //10
		$a_01_1 = {30 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 22 } //10 0:\Program Files\Internet Explorer\IEXPLORE.EXE"
		$a_01_2 = {00 00 53 6f 66 74 77 61 72 65 5c 4d 7a 5c 4f 70 65 6e 49 65 } //5
		$a_01_3 = {00 00 53 6f 66 74 77 61 72 65 5c 58 50 5c 50 61 73 73 69 63 65 } //5
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //3 SOFTWARE\Borland\Delphi\RTL
		$a_01_5 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 41 } //3 InternetOpenUrlA
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3) >=31
 
}