
rule Trojan_BAT_NjRat_NEDP_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 8e 69 18 da 17 d6 8d ?? 00 00 01 0a 03 8e 69 17 da 0b 38 1b 00 00 00 06 07 17 da 02 03 07 91 03 07 17 da 91 65 b5 28 ?? 00 00 06 25 26 9c 07 15 d6 0b 07 17 } //10
		$a_01_1 = {50 6f 6c 79 44 65 43 72 79 70 74 } //2 PolyDeCrypt
		$a_01_2 = {50 6f 6c 79 4d 6f 72 70 68 69 63 53 74 61 69 72 73 } //2 PolyMorphicStairs
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}