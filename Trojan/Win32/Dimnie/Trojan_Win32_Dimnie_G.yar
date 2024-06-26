
rule Trojan_Win32_Dimnie_G{
	meta:
		description = "Trojan:Win32/Dimnie.G,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {5f 44 4d 4e 42 45 47 5f 31 32 33 34 } //02 00  _DMNBEG_1234
		$a_01_1 = {5f 44 4d 4e 45 4e 44 5f } //01 00  _DMNEND_
		$a_01_2 = {73 65 63 6c 69 73 74 2e 73 69 74 65 } //01 00  seclist.site
		$a_01_3 = {70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 31 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 26 00 20 00 } //01 00  ping -n 1 127.0.0.1 && 
		$a_01_4 = {c7 45 f4 61 65 69 6f 33 db 66 c7 45 f8 75 00 c7 45 dc 62 63 64 66 c7 45 e0 67 68 6a 6b } //00 00 
		$a_00_5 = {80 10 } //00 00 
	condition:
		any of ($a_*)
 
}