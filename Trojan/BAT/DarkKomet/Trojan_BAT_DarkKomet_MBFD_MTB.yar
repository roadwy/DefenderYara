
rule Trojan_BAT_DarkKomet_MBFD_MTB{
	meta:
		description = "Trojan:BAT/DarkKomet.MBFD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 0f 08 11 13 9a 28 90 01 01 00 00 0a 11 12 11 13 6f 90 01 01 00 00 0a 6a 61 b7 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 0f 11 13 17 d6 13 13 11 13 11 22 31 cc 90 00 } //1
		$a_01_1 = {75 00 57 00 72 00 43 00 64 00 51 00 69 00 49 00 67 00 52 00 } //1 uWrCdQiIgR
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}