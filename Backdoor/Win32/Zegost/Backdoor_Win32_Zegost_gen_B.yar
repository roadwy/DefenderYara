
rule Backdoor_Win32_Zegost_gen_B{
	meta:
		description = "Backdoor:Win32/Zegost.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 14 01 80 f2 62 88 10 40 90 01 01 75 f4 90 00 } //01 00 
		$a_01_1 = {8b 0f 8a d0 03 c8 80 c2 06 8a 19 32 da 40 3b c6 88 19 7c ec } //01 00 
		$a_01_2 = {83 f8 7f 77 11 83 f8 14 72 0c } //01 00 
		$a_00_3 = {48 74 74 70 2f 31 2e 31 20 34 30 33 20 46 6f 72 62 69 64 64 65 6e } //01 00  Http/1.1 403 Forbidden
		$a_01_4 = {6d 6f 7a 68 65 55 70 64 61 74 65 } //01 00  mozheUpdate
		$a_01_5 = {45 6e 61 62 6c 65 64 00 cf fb cf a2 00 } //01 00 
		$a_01_6 = {5b 46 31 32 5d 00 00 00 5b 46 31 31 5d } //01 00 
		$a_01_7 = {53 65 72 76 69 63 65 4d 61 69 6e 00 6d 61 69 6e } //00 00  敓癲捩䵥楡n慭湩
	condition:
		any of ($a_*)
 
}