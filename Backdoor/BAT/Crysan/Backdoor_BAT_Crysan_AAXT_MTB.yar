
rule Backdoor_BAT_Crysan_AAXT_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 1e 7e 90 01 01 00 00 04 06 08 16 6f 90 01 01 00 00 0a 0d 12 03 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 17 d6 0c 08 07 31 de 7e 90 01 01 00 00 04 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 de 25 90 00 } //01 00 
		$a_01_1 = {47 65 74 50 69 78 65 6c } //00 00  GetPixel
	condition:
		any of ($a_*)
 
}