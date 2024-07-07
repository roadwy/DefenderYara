
rule Trojan_BAT_Tnega_ABGZ_MTB{
	meta:
		description = "Trojan:BAT/Tnega.ABGZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 11 02 16 11 02 8e 69 6f 90 01 03 0a 13 05 20 90 01 03 00 7e 90 01 03 04 7b 90 01 03 04 3a 90 01 03 ff 26 20 90 01 03 00 38 90 01 03 ff 28 90 01 03 06 13 02 38 90 01 03 ff dd 90 01 03 00 11 06 90 00 } //2
		$a_01_1 = {45 00 78 00 76 00 78 00 74 00 77 00 6e 00 64 00 64 00 } //1 Exvxtwndd
		$a_01_2 = {44 00 6b 00 6b 00 71 00 62 00 6c 00 } //1 Dkkqbl
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}