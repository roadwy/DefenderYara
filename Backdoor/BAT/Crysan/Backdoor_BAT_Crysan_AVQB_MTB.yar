
rule Backdoor_BAT_Crysan_AVQB_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AVQB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 25 08 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 11 04 11 05 11 04 8e 69 5d 91 61 d2 81 ?? 00 00 01 11 05 17 58 13 05 11 05 08 8e 69 fe 04 13 15 11 15 2d ce } //4
		$a_03_1 = {0a 13 09 11 09 11 06 6f ?? 00 00 0a 00 11 09 11 07 6f ?? 00 00 0a 00 11 09 17 6f ?? 00 00 0a 00 11 09 18 6f ?? 00 00 0a 00 11 09 6f ?? 00 00 0a 11 08 16 11 08 8e 69 6f ?? 00 00 0a 13 0a } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}