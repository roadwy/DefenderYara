
rule Trojan_BAT_QuasarRat_JKU_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.JKU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e da 00 00 04 0c 00 00 07 6f a2 00 00 0a 72 e5 55 00 70 6f a3 00 00 0a 00 07 6f a2 00 00 0a 72 f5 55 00 70 08 72 e0 2a 00 70 28 7b 00 00 0a 6f a4 00 00 0a 00 07 6f a2 00 00 0a 16 6f b9 01 00 0a 00 07 6f a6 00 00 0a 26 } //2
		$a_00_1 = {54 00 57 00 56 00 30 00 61 00 47 00 39 00 6b 00 4d 00 41 00 3d 00 3d 00 } //2 TWV0aG9kMA==
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}