
rule Backdoor_Win32_Zegost_DB{
	meta:
		description = "Backdoor:Win32/Zegost.DB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 11 80 ea 90 01 01 8b 45 fc 03 45 f8 88 10 8b 4d fc 03 4d f8 8a 11 80 f2 90 01 01 8b 45 fc 03 45 f8 88 10 eb 90 00 } //01 00 
		$a_01_1 = {c6 00 4d 8b 4d 08 c6 41 01 5a 8b 55 08 89 55 ec 8b 45 ec 33 c9 66 8b 08 81 f9 4d 5a 00 00 74 } //01 00 
		$a_01_2 = {6e 75 52 5c 6e 6f 69 73 72 65 56 74 6e 65 72 72 75 43 5c 73 77 6f 64 6e 69 57 5c 74 66 6f 73 6f 72 63 69 4d 5c 45 52 41 57 54 46 4f 53 00 } //00 00  畮屒潮獩敲瑖敮牲䍵獜潷湤坩瑜潦潳捲䵩䕜䅒呗但S
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}