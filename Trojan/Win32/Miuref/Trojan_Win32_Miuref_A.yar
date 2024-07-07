
rule Trojan_Win32_Miuref_A{
	meta:
		description = "Trojan:Win32/Miuref.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 25 73 25 69 2e 25 69 2e 25 69 2e 25 69 2f 00 } //1
		$a_03_1 = {c6 06 7b ff 37 8d 46 01 6a 90 01 01 6a 90 01 01 50 e8 90 01 04 c6 46 09 2d 0f b7 47 04 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Miuref_A_2{
	meta:
		description = "Trojan:Win32/Miuref.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 83 3c 4e 5c 75 03 89 4d fc 41 3b c8 72 f1 } //2
		$a_01_1 = {73 00 65 00 74 00 75 00 70 00 2e 00 64 00 61 00 74 00 } //2 setup.dat
		$a_01_2 = {b8 4d 5a 00 00 66 39 45 00 75 f1 56 8b 75 3c 03 f5 81 3e 50 45 00 00 74 07 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}