
rule Trojan_BAT_Zilla_AC_MTB{
	meta:
		description = "Trojan:BAT/Zilla.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 72 00 00 0a 25 11 04 6f 73 00 00 0a 25 17 6f 76 00 00 0a 25 16 6f 88 00 00 0a 25 17 6f 75 00 00 0a 28 89 00 00 0a 26 20 f4 01 00 00 28 1b 00 00 0a 16 28 1c 00 00 0a de 0b } //6
		$a_81_1 = {43 6c 69 65 6e 74 2e 65 78 65 } //2 Client.exe
		$a_81_2 = {4b 65 79 6c 6f 67 67 65 72 } //2 Keylogger
		$a_81_3 = {63 6d 64 64 69 73 61 62 6c 65 } //2 cmddisable
	condition:
		((#a_01_0  & 1)*6+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2) >=12
 
}