
rule Trojan_BAT_Crysan_GILCH_MTB{
	meta:
		description = "Trojan:BAT/Crysan.GILCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 42 cd 48 07 61 25 13 0c 1f 17 5e 45 17 00 00 00 15 01 00 00 a1 01 00 00 60 01 00 00 01 02 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}