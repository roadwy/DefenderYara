
rule Backdoor_WinNT_Haxdoor_gen_A{
	meta:
		description = "Backdoor:WinNT/Haxdoor.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 39 10 74 07 2d 00 10 00 00 eb } //1
		$a_03_1 = {83 ee 05 89 72 01 8b 81 ?? ?? ?? ?? 66 83 38 8b } //1
		$a_01_2 = {42 ba 77 77 77 2e 39 11 75 } //1
		$a_01_3 = {83 fa 0b 76 1a 81 78 f6 6f 00 74 00 } //1
		$a_01_4 = {82 1c 05 46 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}