
rule Trojan_BAT_DarkTortilla_RPX_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 0a 75 0c 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 0c 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 } //1
		$a_01_1 = {67 65 74 5f 57 68 69 74 65 53 6d 6f 6b 65 } //1 get_WhiteSmoke
		$a_01_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_5 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_01_6 = {67 65 74 5f 44 61 72 6b 53 65 61 47 72 65 65 6e } //1 get_DarkSeaGreen
		$a_01_7 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}