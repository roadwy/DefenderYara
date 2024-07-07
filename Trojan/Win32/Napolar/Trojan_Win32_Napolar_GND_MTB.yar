
rule Trojan_Win32_Napolar_GND_MTB{
	meta:
		description = "Trojan:Win32/Napolar.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 53 30 40 } //1 j@hS0@
		$a_01_1 = {6a 40 68 2e 31 40 } //1 j@h.1@
		$a_01_2 = {6a 40 68 58 31 40 } //1 j@hX1@
		$a_01_3 = {6c 6f 6e 67 6b 65 79 64 6f 65 73 6e 74 6d 61 74 74 65 72 33 34 33 31 31 33 31 } //1 longkeydoesntmatter3431131
		$a_01_4 = {74 65 73 74 2e 74 78 74 20 65 6e 63 72 79 70 74 65 64 20 61 73 20 74 65 73 74 2e 74 78 74 } //1 test.txt encrypted as test.txt
		$a_01_5 = {68 69 20 68 6f 77 20 61 72 65 20 79 6f 75 20 65 6e 63 72 79 70 74 65 64 20 61 73 20 25 73 } //1 hi how are you encrypted as %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}