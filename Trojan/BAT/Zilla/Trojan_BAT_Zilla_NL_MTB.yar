
rule Trojan_BAT_Zilla_NL_MTB{
	meta:
		description = "Trojan:BAT/Zilla.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {28 11 00 00 0a 02 6f 49 00 00 0a 0b 06 07 6f 4a 00 00 0a 0c 73 4b 00 00 0a 0d 28 46 00 00 06 13 04 2b 28 09 08 11 04 8f 4d 00 00 01 28 e4 05 00 06 28 bb 05 00 06 28 4c 00 00 0a 6f 4d 00 00 0a 26 11 04 28 47 00 00 06 58 13 04 11 04 08 8e 69 32 d1 } //3
		$a_01_1 = {38 39 2e 32 33 2e 31 30 30 2e 32 33 33 } //1 89.23.100.233
		$a_01_2 = {65 6e 63 72 79 70 74 65 64 } //1 encrypted
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}