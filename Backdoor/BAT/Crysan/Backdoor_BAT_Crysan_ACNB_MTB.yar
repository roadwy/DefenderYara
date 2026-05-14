
rule Backdoor_BAT_Crysan_ACNB_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.ACNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0e 09 00 fe 0c 09 00 20 00 00 00 00 fe 0c 04 00 a2 fe 0c 09 00 20 01 00 00 00 fe 0c 05 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 02 00 00 00 fe 0c 06 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 03 00 00 00 fe 0c 07 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 20 04 00 00 00 fe 0c 08 00 fe 0c 02 00 20 01 00 00 00 28 ?? 00 00 0a a2 fe 0c 09 00 28 ?? 00 00 0a fe 0e 04 00 fe 0c 02 00 20 01 00 00 00 d6 fe 0e 02 00 fe 0c 02 00 fe 0c 03 00 3e } //4
		$a_01_1 = {11 09 11 0e 8f 19 00 00 01 25 71 19 00 00 01 11 0c 11 0e 91 61 d2 81 19 00 00 01 11 0e 17 58 13 0e 11 0e 11 08 32 d9 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}