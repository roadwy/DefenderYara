
rule Trojan_BAT_ClipBanker_NE_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 54 00 00 0a 11 20 17 6f 55 00 00 0a 13 21 11 21 72 40 38 00 70 6f 56 00 00 0a 2d 20 7e 54 00 00 0a 11 20 6f 57 00 00 0a 72 40 38 00 70 28 58 00 00 0a 6f 29 00 00 0a 6f 59 00 00 0a de 0c } //1
		$a_01_1 = {11 16 28 5d 00 00 0a 6f 5f 00 00 0a 2c 0f 72 57 8b 00 70 28 08 00 00 06 38 bf 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}