
rule Backdoor_Win32_Lisuife_A_dha{
	meta:
		description = "Backdoor:Win32/Lisuife.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {69 73 20 79 6f 75 20 6c 69 76 65 } //01 00  is you live
		$a_03_1 = {b9 80 96 98 00 f7 f9 03 d3 52 e8 90 01 04 83 c4 08 e8 90 01 04 99 b9 60 00 00 00 90 00 } //01 00 
		$a_03_2 = {b9 80 96 98 00 f7 f9 03 f2 56 e8 90 01 04 83 c4 04 e8 90 01 04 99 b9 60 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}