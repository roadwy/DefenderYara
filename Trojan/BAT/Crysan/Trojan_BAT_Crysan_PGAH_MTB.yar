
rule Trojan_BAT_Crysan_PGAH_MTB{
	meta:
		description = "Trojan:BAT/Crysan.PGAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e 1a 01 00 04 0e 06 17 59 e0 95 58 0e 05 28 f2 02 00 06 58 54 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}