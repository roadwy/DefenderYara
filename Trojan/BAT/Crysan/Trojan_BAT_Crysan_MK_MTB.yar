
rule Trojan_BAT_Crysan_MK_MTB{
	meta:
		description = "Trojan:BAT/Crysan.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0b 9a 13 0c 00 06 11 0c 6f 21 00 00 0a 28 22 00 00 0a 13 0d 11 09 11 0c 6f 23 00 00 0a 11 0d 6f 24 00 00 0a 00 00 11 0b 17 58 13 0b 11 0b 11 0a 8e 69 32 c9 } //35
	condition:
		((#a_01_0  & 1)*35) >=35
 
}