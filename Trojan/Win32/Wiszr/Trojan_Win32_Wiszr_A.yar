
rule Trojan_Win32_Wiszr_A{
	meta:
		description = "Trojan:Win32/Wiszr.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 69 73 77 69 7a 61 72 64 2e 37 7a 00 } //01 00 
		$a_03_1 = {70 72 6f 63 65 78 70 2e 65 78 65 90 05 04 01 00 74 61 73 6b 6d 67 72 2e 65 78 65 90 00 } //01 00 
		$a_01_2 = {00 6d 69 6e 65 72 20 55 49 44 00 } //01 00 
		$a_01_3 = {64 77 6d 2e 65 78 65 20 2d 70 6f 6f 6c } //00 00  dwm.exe -pool
	condition:
		any of ($a_*)
 
}