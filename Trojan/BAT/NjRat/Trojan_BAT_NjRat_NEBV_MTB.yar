
rule Trojan_BAT_NjRat_NEBV_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 0a 2b 1b 00 7e 36 00 00 04 06 7e 36 00 00 04 06 91 20 51 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e 36 00 00 04 8e 69 fe 04 0b 07 2d d7 } //10
		$a_01_1 = {73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 } //5 s://cdn.dis
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}