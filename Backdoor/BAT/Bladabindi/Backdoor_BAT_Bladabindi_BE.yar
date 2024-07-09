
rule Backdoor_BAT_Bladabindi_BE{
	meta:
		description = "Backdoor:BAT/Bladabindi.BE,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 50 45 } //1 RunPE
		$a_01_1 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 } //1 [ENTER]
		$a_01_2 = {7b 00 31 00 31 00 31 00 31 00 31 00 2d 00 32 00 32 00 32 00 32 00 32 00 2d 00 35 00 30 00 30 00 30 00 31 00 2d 00 30 00 30 00 30 00 30 00 30 00 7d 00 } //1 {11111-22222-50001-00000}
		$a_03_3 = {1f 1d 0f 00 1a 28 ?? 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}