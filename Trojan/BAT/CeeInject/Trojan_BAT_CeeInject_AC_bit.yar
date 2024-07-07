
rule Trojan_BAT_CeeInject_AC_bit{
	meta:
		description = "Trojan:BAT/CeeInject.AC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 42 00 73 65 74 5f 42 00 67 65 74 5f 4b 00 73 65 74 5f 4b } //1
		$a_03_1 = {49 6e 76 6f 6b 65 90 02 10 41 70 70 44 6f 6d 61 69 6e 00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00 4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 90 00 } //1
		$a_01_2 = {06 d3 08 58 06 d3 08 58 47 07 d3 08 02 28 04 00 00 06 8e 69 5d 58 47 61 d2 52 08 17 58 0c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}