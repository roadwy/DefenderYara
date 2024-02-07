
rule Trojan_Win32_Bladabindi_ARAC_MTB{
	meta:
		description = "Trojan:Win32/Bladabindi.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {36 50 30 4d 61 33 49 58 } //02 00  6P0Ma3IX
		$a_01_1 = {2f 3a 2f 43 51 30 4a 58 2c 46 56 31 56 64 32 57 65 30 53 61 34 54 63 34 51 } //02 00  /:/CQ0JX,FV1Vd2We0Sa4Tc4Q
		$a_01_2 = {29 46 55 27 41 51 30 4d 56 2b 48 51 27 40 4c } //00 00  )FU'AQ0MV+HQ'@L
	condition:
		any of ($a_*)
 
}