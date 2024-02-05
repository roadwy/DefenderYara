
rule Trojan_Win32_Danginex{
	meta:
		description = "Trojan:Win32/Danginex,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 78 6d 6c 5f 6c 6f 73 74 5f 61 64 2e 61 73 70 3f 61 64 5f 75 72 6c 3d } //01 00 
		$a_01_1 = {6e 69 75 64 6f 75 64 6f 75 2e 63 6f 6d 2f 77 65 62 2f 67 65 74 69 6e 66 6f 2e 61 73 70 3f 76 65 72 3d 25 64 } //01 00 
		$a_01_2 = {6e 69 75 64 6f 75 64 6f 75 2e 63 6f 6d 2f 77 65 62 2f 75 70 64 61 74 65 75 73 65 72 2e 61 73 70 3f 69 64 3d } //01 00 
		$a_01_3 = {54 52 53 4f 43 52 5f 69 6e 69 2e 64 6c 6c } //01 00 
		$a_01_4 = {54 52 53 4f 43 52 5f 64 61 74 61 2e 64 6c 6c } //01 00 
		$a_01_5 = {41 64 76 4f 63 72 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}