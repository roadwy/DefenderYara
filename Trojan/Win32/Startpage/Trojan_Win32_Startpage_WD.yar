
rule Trojan_Win32_Startpage_WD{
	meta:
		description = "Trojan:Win32/Startpage.WD,SIGNATURE_TYPE_PEHSTR,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 6f 67 6f 75 45 78 70 6c 6f 72 65 72 } //01 00 
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 33 36 30 73 65 5c 33 36 30 53 45 2e 69 6e 69 } //01 00 
		$a_01_2 = {2e 37 37 36 6c 61 2e 63 6f 6d } //01 00 
		$a_01_3 = {49 65 73 65 2e 74 6d 70 } //01 00 
		$a_01_4 = {64 68 2e 61 64 32 39 2e 63 6f 6d 2f 3f 69 64 3d } //00 00 
	condition:
		any of ($a_*)
 
}