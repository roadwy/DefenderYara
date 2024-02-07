
rule Backdoor_Win32_Zegost_DG{
	meta:
		description = "Backdoor:Win32/Zegost.DG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 4b 5f 75 73 65 72 47 68 6f 61 6b 00 } //01 00 
		$a_01_1 = {8b 4d 08 8a 11 32 55 fc 8b 45 08 88 10 8b 4d 08 8a 11 02 55 fc 8b 45 08 88 10 8b 4d 08 83 c1 01 } //01 00 
		$a_03_2 = {83 ec 0c c6 45 90 01 01 44 c6 45 90 01 01 6c c6 45 90 01 01 6c c6 45 90 01 01 41 c6 45 90 01 01 75 c6 45 90 01 01 64 c6 45 90 01 01 69 c6 45 90 01 01 6f c6 45 90 01 01 00 90 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}