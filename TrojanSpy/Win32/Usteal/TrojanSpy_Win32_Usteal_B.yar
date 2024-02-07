
rule TrojanSpy_Win32_Usteal_B{
	meta:
		description = "TrojanSpy:Win32/Usteal.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 46 52 5f 53 74 65 61 6c 65 72 5f 32 33 31 30 00 } //01 00 
		$a_01_1 = {52 65 67 69 73 74 72 79 2d 47 72 61 62 62 69 6e 67 2e 72 65 67 00 } //01 00 
		$a_01_2 = {25 30 32 68 75 2d 25 30 32 68 75 2d 25 68 75 5f 25 30 32 68 75 2d 25 30 32 68 75 2d 25 30 32 68 75 00 } //01 00 
		$a_01_3 = {44 69 73 70 6c 61 79 4e 61 6d 65 00 54 72 6f 6c 6f 6c 6f 00 } //00 00  楄灳慬乹浡e牔汯汯o
	condition:
		any of ($a_*)
 
}