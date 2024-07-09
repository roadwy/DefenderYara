
rule Trojan_BAT_FormBook_IRK_MTB{
	meta:
		description = "Trojan:BAT/FormBook.IRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 16 28 02 00 0d 2b 0f 00 08 07 09 28 ?? ?? ?? 06 0b 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d e4 } //1
		$a_01_1 = {00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 00 } //1
		$a_01_2 = {35 00 47 00 5a 00 47 00 34 00 42 00 54 00 50 00 48 00 5a 00 41 00 42 00 43 00 47 00 37 00 35 00 35 00 4f 00 56 00 51 00 5a 00 54 00 } //1 5GZG4BTPHZABCG755OVQZT
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //1 Invoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}