
rule Trojan_Win32_BHO_AR{
	meta:
		description = "Trojan:Win32/BHO.AR,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 62 61 72 73 65 61 72 63 68 2e 63 6f 2e 6b 72 2f 50 72 6f 2f 63 6e 74 2e 70 68 70 3f 6d 61 63 3d 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 62 61 72 73 63 } //01 00 
		$a_01_1 = {42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 7b 33 41 42 42 38 45 38 42 2d 36 38 35 32 2d 34 38 31 46 2d 38 41 37 34 2d 31 38 42 41 42 43 41 37 41 37 34 42 } //01 00  Browser Helper Objects\{3ABB8E8B-6852-481F-8A74-18BABCA7A74B
		$a_01_2 = {68 74 74 70 3a 2f 2f 69 6e 73 74 61 6c 6c 32 2e 6d 64 76 69 72 75 73 2e 63 6f 6d 2f 44 42 2f } //01 00  http://install2.mdvirus.com/DB/
		$a_01_3 = {25 73 20 2f 73 20 2f 75 20 25 73 } //00 00  %s /s /u %s
	condition:
		any of ($a_*)
 
}