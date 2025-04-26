
rule Trojan_BAT_Bulz_KAA_MTB{
	meta:
		description = "Trojan:BAT/Bulz.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e7 } //5
		$a_01_1 = {11 04 11 11 11 04 11 11 91 1f 7a 61 d2 9c 11 11 17 58 13 11 11 11 11 04 8e 69 32 e4 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}