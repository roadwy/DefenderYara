
rule Trojan_Win32_Startpage_LT{
	meta:
		description = "Trojan:Win32/Startpage.LT,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 43 6c 65 61 72 4f 6e 46 69 6c 65 00 68 74 74 70 3a 2f 2f 77 76 77 2e 6a 73 73 6e 73 2e 63 6f 6d 2f 69 6e 64 65 78 2e 68 74 6d 3f 34 30 32 00 } //01 00 
		$a_01_1 = {00 49 6e 74 65 72 6e 65 74 53 68 6f 72 74 63 75 74 00 55 52 4c 00 68 74 74 70 3a 2f 2f 77 76 77 2e 65 79 75 79 75 2e 63 6f 6d 2f 3f 34 30 32 00 } //01 00 
		$a_01_2 = {73 70 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 6b 6f 32 32 33 33 2e 63 6f 6d 2f } //00 00 
	condition:
		any of ($a_*)
 
}