
rule Trojan_Win32_Startpage_EX{
	meta:
		description = "Trojan:Win32/Startpage.EX,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 73 6f 66 74 2e 63 33 39 33 63 2e 63 6e 2f 6e 65 77 75 70 33 2e 74 78 74 } //01 00 
		$a_00_1 = {4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //01 00 
		$a_00_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 } //01 00 
		$a_02_3 = {7a 68 61 6f 90 02 01 2e 6e 65 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}