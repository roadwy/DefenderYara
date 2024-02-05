
rule Trojan_Win32_Startpage_LU{
	meta:
		description = "Trojan:Win32/Startpage.LU,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 41 53 45 55 52 4c 3d 20 68 74 74 70 3a 2f 2f 77 77 77 2e 35 32 30 35 36 30 2e 63 6f 6d } //01 00 
		$a_01_1 = {49 63 6f 6e 46 69 6c 65 3d 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 } //01 00 
		$a_01_2 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 } //00 00 
	condition:
		any of ($a_*)
 
}