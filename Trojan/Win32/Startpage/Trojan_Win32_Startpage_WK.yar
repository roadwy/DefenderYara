
rule Trojan_Win32_Startpage_WK{
	meta:
		description = "Trojan:Win32/Startpage.WK,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {51 2d 24 2d 45 58 45 } //01 00 
		$a_01_1 = {64 65 6c 20 25 30 } //01 00 
		$a_01_2 = {51 38 38 38 2e 64 6c 6c } //01 00 
		$a_01_3 = {51 39 39 39 2e 64 6c 6c } //01 00 
		$a_01_4 = {78 6c 6f 6f 6f 2e 64 6c 6c } //01 00 
		$a_01_5 = {78 6c 6e 6e 6e 2e 64 6c 6c } //01 00 
		$a_01_6 = {31 37 34 2e 31 33 39 2e 32 2e 32 33 36 2f 47 6f 2e 61 73 68 78 3f 4d 61 63 3d } //00 00 
	condition:
		any of ($a_*)
 
}