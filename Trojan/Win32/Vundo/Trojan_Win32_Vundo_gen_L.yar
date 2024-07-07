
rule Trojan_Win32_Vundo_gen_L{
	meta:
		description = "Trojan:Win32/Vundo.gen!L,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 e6 10 d2 70 } //2
		$a_01_1 = {68 fe 6a 7a 69 } //1
		$a_01_2 = {68 e1 1f f7 5a } //2
		$a_01_3 = {68 62 67 8d a4 } //1
		$a_01_4 = {68 5f 70 35 3a } //1 h_p5:
		$a_01_5 = {68 5a 6f de a9 } //1
		$a_01_6 = {68 ee ea c0 1f } //1
		$a_01_7 = {68 bd 4d 54 7d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=6
 
}