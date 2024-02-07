
rule Backdoor_BAT_Bladabindi_BE{
	meta:
		description = "Backdoor:BAT/Bladabindi.BE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 45 } //01 00  RunPE
		$a_01_1 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } //01 00  [ENTER]
		$a_01_2 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 30 00 7d 00 } //01 00  {11111-22222-50001-00000}
		$a_03_3 = {1f 1d 0f 00 1a 28 90 01 01 00 00 06 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 d7 
	condition:
		any of ($a_*)
 
}