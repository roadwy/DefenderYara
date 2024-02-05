
rule Trojan_Win32_SpyStealer_AM_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 fe 73 e6 01 00 75 05 e8 90 02 04 46 81 fe 9e e7 03 00 7c c3 90 00 } //02 00 
		$a_01_1 = {81 fe ee 75 37 00 7f 09 46 81 fe f6 ea 2b 33 7c 94 } //01 00 
		$a_01_2 = {57 69 70 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_3 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00 
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00 
		$a_01_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}