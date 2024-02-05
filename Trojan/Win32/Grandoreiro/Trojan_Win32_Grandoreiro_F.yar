
rule Trojan_Win32_Grandoreiro_F{
	meta:
		description = "Trojan:Win32/Grandoreiro.F,SIGNATURE_TYPE_PEHSTR_EXT,29 00 29 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_00_1 = {44 45 4c 45 54 41 4b 4c } //0a 00 
		$a_00_2 = {41 54 49 56 41 52 43 41 50 54 55 52 41 4d 41 47 } //0a 00 
		$a_00_3 = {52 65 69 6e 31 63 31 61 53 79 73 74 65 6d } //0a 00 
		$a_00_4 = {42 4c 4f 51 55 45 52 41 43 45 53 53 4f 42 41 4e 4b 49 4e 54 45 52 } //00 00 
		$a_00_5 = {5d 04 00 00 12 42 05 80 5c 29 00 00 13 42 05 80 00 00 01 00 08 00 13 00 ac 21 47 72 61 6e 64 6f 72 65 69 72 6f 2e 46 21 } //73 6d 
	condition:
		any of ($a_*)
 
}