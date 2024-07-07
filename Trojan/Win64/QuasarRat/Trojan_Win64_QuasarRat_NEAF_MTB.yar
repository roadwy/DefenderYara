
rule Trojan_Win64_QuasarRat_NEAF_MTB{
	meta:
		description = "Trojan:Win64/QuasarRat.NEAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 18 4c 89 e9 48 89 fa 49 89 f0 e8 f3 88 00 00 30 18 48 89 ef eb d1 } //10
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2d 31 65 63 63 36 32 39 39 64 62 39 65 63 38 32 33 } //5 github.com-1ecc6299db9ec823
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}