
rule Trojan_Win32_Servswin_A{
	meta:
		description = "Trojan:Win32/Servswin.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 69 6e 73 65 72 76 69 63 65 73 2e 65 78 65 00 6f 70 65 6e 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_01_3 = {76 73 6f 6c 6c 6f 2d 65 6f 6d } //01 00 
		$a_01_4 = {68 68 5f 6d 6d 5f 73 73 5f 74 74 } //00 00 
	condition:
		any of ($a_*)
 
}