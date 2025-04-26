
rule Trojan_BAT_FormBook_MBYZ_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 00 6f 00 00 05 61 00 64 00 00 03 3f 00 00 03 42 00 00 03 3a 00 00 05 41 00 41 } //7
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {53 70 6c 69 74 } //1 Split
		$a_01_3 = {47 72 61 66 69 6b 5f 53 69 73 74 65 6d 69 } //1 Grafik_Sistemi
	condition:
		((#a_01_0  & 1)*7+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=10
 
}