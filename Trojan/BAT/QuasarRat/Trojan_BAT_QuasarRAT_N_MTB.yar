
rule Trojan_BAT_QuasarRAT_N_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 bf a3 3f 09 1f 00 00 00 ba 01 33 00 16 00 00 01 00 00 00 b4 00 00 00 e0 00 00 00 5d 04 00 00 c0 05 } //2
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}