
rule Trojan_Win32_Fragtor_AMME_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.AMME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 73 6a 65 65 5f 73 75 77 66 73 } //01 00  bisjee_suwfs
		$a_01_1 = {61 73 65 67 75 69 66 61 65 68 67 69 67 68 } //01 00  aseguifaehgigh
		$a_01_2 = {76 69 61 65 67 6a 61 65 77 67 5f 61 65 69 66 67 61 6a 65 } //01 00  viaegjaewg_aeifgaje
		$a_01_3 = {78 63 76 75 79 62 69 72 5f 73 75 69 66 77 } //00 00  xcvuybir_suifw
	condition:
		any of ($a_*)
 
}