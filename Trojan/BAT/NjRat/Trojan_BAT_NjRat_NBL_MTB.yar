
rule Trojan_BAT_NjRat_NBL_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 e2 5f 85 cd 65 20 d8 9a 7e 28 61 20 3a c5 fb e5 58 17 62 13 05 } //1
		$a_01_1 = {20 dd f2 d6 37 20 40 af 40 10 59 20 1d 43 96 27 61 1a 63 19 63 07 5b 0b } //1
		$a_01_2 = {20 b9 e4 fb 48 20 06 ba 66 21 59 65 20 1d 6f a2 10 58 20 95 bb f2 16 61 66 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}