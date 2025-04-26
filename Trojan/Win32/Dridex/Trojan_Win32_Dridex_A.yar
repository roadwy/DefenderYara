
rule Trojan_Win32_Dridex_A{
	meta:
		description = "Trojan:Win32/Dridex.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 45 56 5c 53 4f 46 54 5c 44 45 42 55 47 2e 70 64 62 } //1 DEV\SOFT\DEBUG.pdb
		$a_01_1 = {46 75 63 6b 54 68 65 50 6f 6c 69 63 65 } //1 FuckThePolice
		$a_01_2 = {42 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 37 00 56 00 66 00 6f 00 72 00 58 00 63 00 79 00 63 00 6c 00 65 00 } //1 BSecurity7VforXcycle
		$a_01_3 = {51 00 5a 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 46 00 72 00 65 00 6d 00 61 00 72 00 6b 00 73 00 6d 00 65 00 61 00 6e 00 69 00 6e 00 67 00 6b 00 61 00 6e 00 64 00 6b 00 } //1 QZpasswordFremarksmeaningkandk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}