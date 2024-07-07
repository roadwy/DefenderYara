
rule Trojan_BAT_Disstl_EM_MTB{
	meta:
		description = "Trojan:BAT/Disstl.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {16 0a 02 28 26 00 00 06 25 20 00 80 00 00 5f 20 00 80 00 00 33 04 06 17 60 0a 17 5f 17 33 04 06 18 60 0a 06 2a } //10
		$a_80_1 = {6b 65 79 4c 6f 67 67 65 72 } //keyLogger  3
		$a_80_2 = {53 70 79 77 61 72 65 } //Spyware  3
		$a_80_3 = {49 73 4b 65 79 54 6f 67 67 6c 65 64 } //IsKeyToggled  3
		$a_80_4 = {47 65 74 4b 65 79 53 74 61 74 65 } //GetKeyState  3
		$a_80_5 = {69 73 4b 65 79 44 6f 77 6e } //isKeyDown  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}