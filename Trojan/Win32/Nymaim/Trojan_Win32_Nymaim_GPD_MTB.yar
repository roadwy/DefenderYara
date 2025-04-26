
rule Trojan_Win32_Nymaim_GPD_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {df e2 20 38 ee ce 16 b6 98 cf 59 2d 66 98 73 78 d7 5a b6 91 66 b5 e4 e1 bd 87 fc fb ff df bf } //5
		$a_01_1 = {73 de c7 8b c8 9a 19 b1 37 65 8a 23 a5 32 94 b9 48 7d 19 ef 79 e2 c4 7b 79 7e 41 8c c3 48 0c a6 2e 04 46 9c d9 3c c9 c7 c0 7a 39 32 f6 a3 4a a9 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}