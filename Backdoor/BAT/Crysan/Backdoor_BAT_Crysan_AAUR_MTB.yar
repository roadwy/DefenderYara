
rule Backdoor_BAT_Crysan_AAUR_MTB{
	meta:
		description = "Backdoor:BAT/Crysan.AAUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 72 0d 00 00 70 6f 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 72 c2 00 00 70 73 90 01 01 00 00 0a 0d 08 09 6f 90 01 01 00 00 0a 13 04 1a 8d 90 01 01 00 00 01 25 16 72 75 01 00 70 a2 25 17 7e 90 01 01 00 00 0a a2 25 18 11 04 a2 25 19 17 8c 90 01 01 00 00 01 a2 13 05 14 13 07 28 90 01 01 00 00 0a 07 6f 90 01 01 00 00 0a 13 06 90 00 } //01 00 
		$a_01_1 = {41 00 6e 00 61 00 73 00 61 00 79 00 66 00 61 00 2e 00 73 00 6f 00 6f 00 6e 00 65 00 72 00 } //00 00  Anasayfa.sooner
	condition:
		any of ($a_*)
 
}