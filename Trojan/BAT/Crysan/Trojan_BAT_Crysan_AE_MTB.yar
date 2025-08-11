
rule Trojan_BAT_Crysan_AE_MTB{
	meta:
		description = "Trojan:BAT/Crysan.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 a6 c5 6b cd 80 9e 00 00 04 17 80 9f 00 00 04 72 d7 0a 00 70 80 a0 00 00 04 17 80 a1 00 00 04 72 05 0b 00 70 80 a2 00 00 04 21 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}