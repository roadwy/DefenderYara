
rule Backdoor_Win32_Zegost_DN{
	meta:
		description = "Backdoor:Win32/Zegost.DN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 ec 2c 01 00 00 c6 45 90 01 01 5c c6 45 90 01 01 6f c6 45 90 01 01 75 c6 45 90 01 01 72 c6 45 90 01 01 6c c6 45 90 01 01 6f c6 45 90 01 01 67 c6 45 90 01 01 2e c6 45 90 01 01 64 c6 45 90 01 01 61 c6 45 90 01 01 74 c6 45 90 01 01 00 90 00 } //01 00 
		$a_01_1 = {8b 4d 08 03 8d 70 ff ff ff 8a 11 32 94 45 7c ff ff ff 8b 45 08 03 85 70 ff ff ff 88 10 66 8b 4d ec 66 83 c1 01 66 89 4d ec eb 91 } //01 00 
		$a_01_2 = {56 49 50 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 00 00 78 37 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}