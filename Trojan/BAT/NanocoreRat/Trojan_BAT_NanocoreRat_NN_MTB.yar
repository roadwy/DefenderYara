
rule Trojan_BAT_NanocoreRat_NN_MTB{
	meta:
		description = "Trojan:BAT/NanocoreRat.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 08 11 0a 8f 18 00 00 01 25 71 18 00 00 01 08 d2 61 d2 81 18 00 00 01 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 32 c5 } //5
		$a_80_1 = {4e 61 6e 6f 43 6f 72 65 } //NanoCore  5
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}