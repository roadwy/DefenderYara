
rule Trojan_Win32_Startpage_XH{
	meta:
		description = "Trojan:Win32/Startpage.XH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 79 73 69 6e 66 6f 2e 74 6d 70 } //01 00 
		$a_01_1 = {5c 72 75 6e 64 31 6c 33 32 2e 65 78 65 } //01 00 
		$a_01_2 = {2e 67 6f 6f 64 75 62 61 69 2e 63 6f 6d 2f 3f } //01 00 
		$a_01_3 = {5c 44 46 46 41 46 31 42 46 43 34 34 62 30 31 42 41 31 44 31 38 31 38 36 42 37 46 31 37 33 33 } //01 00 
		$a_03_4 = {5c 64 61 65 6d 6f 6e 2e 65 78 65 90 01 01 5c 73 79 73 74 65 6d 36 34 2e 2e 5c 90 01 04 5c 73 79 73 74 65 6d 36 34 5c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}