
rule Trojan_BAT_NjRat_NECT_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NECT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {00 00 70 28 07 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03 26 de d3 07 2a } //10
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_2 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_3 = {43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 73 00 } //1 Comments
		$a_01_4 = {49 6e 76 6f 6b 65 72 } //1 Invoker
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}