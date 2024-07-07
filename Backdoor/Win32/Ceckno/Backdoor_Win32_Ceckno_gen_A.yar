
rule Backdoor_Win32_Ceckno_gen_A{
	meta:
		description = "Backdoor:Win32/Ceckno.gen!A,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 61 64 65 20 69 6e 20 43 68 69 6e 61 20 44 44 6f 53 } //1 Made in China DDoS
		$a_01_1 = {57 69 6e 64 6f 77 73 20 43 68 69 6e 61 20 44 72 69 76 65 72 } //1 Windows China Driver
		$a_01_2 = {4e 65 74 77 6f 72 6b 20 43 68 69 6e 61 20 4e 65 74 42 6f 74 } //1 Network China NetBot
		$a_01_3 = {68 c0 30 40 00 68 40 30 40 00 68 20 30 40 00 } //5
		$a_01_4 = {62 00 00 00 5c 78 63 6f 70 79 2e 65 78 65 00 00 5c 6e 74 73 65 72 76 65 72 2e 65 78 65 00 00 00 45 58 45 00 5c 6e 74 73 65 72 76 65 72 2e 64 6c } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5) >=11
 
}