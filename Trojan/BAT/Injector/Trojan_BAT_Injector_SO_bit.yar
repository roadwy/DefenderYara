
rule Trojan_BAT_Injector_SO_bit{
	meta:
		description = "Trojan:BAT/Injector.SO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5f d8 06 1e 63 d6 0a 08 1d d6 07 20 ff 00 00 00 5f d8 07 1e 63 d6 0b 06 1e 62 07 d6 20 ff 00 00 00 5f 0c 11 04 11 06 02 11 06 91 08 b4 61 } //1
		$a_01_1 = {47 5a 69 70 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00 } //1
		$a_01_2 = {53 65 76 65 6e 5a 69 70 48 65 6c 70 65 72 00 53 65 76 65 6e 5a 69 70 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 2e 4c 5a 4d 41 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}