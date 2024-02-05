
rule Backdoor_WinNT_Haxdoor_gen_A{
	meta:
		description = "Backdoor:WinNT/Haxdoor.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 39 10 74 07 2d 00 10 00 00 eb } //01 00 
		$a_03_1 = {83 ee 05 89 72 01 8b 81 90 01 04 66 83 38 8b 90 00 } //01 00 
		$a_01_2 = {42 ba 77 77 77 2e 39 11 75 } //01 00 
		$a_01_3 = {83 fa 0b 76 1a 81 78 f6 6f 00 74 00 } //01 00 
		$a_01_4 = {82 1c 05 46 e8 } //00 00 
	condition:
		any of ($a_*)
 
}