
rule Trojan_Win32_Vidar_ND_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_81_0 = {6a 75 68 69 6a 69 74 } //2 juhijit
		$a_81_1 = {77 6f 6e 75 62 61 6a 69 63 69 63 65 67 6f 64 6f 6e 69 70 75 74 } //1 wonubajicicegodoniput
		$a_81_2 = {64 69 68 75 76 6f 73 75 73 6f 78 75 79 65 76 6f 68 69 67 6f 72 61 6c 65 77 69 66 6f 7a 75 68 } //1 dihuvosusoxuyevohigoralewifozuh
		$a_81_3 = {6e 61 6b 61 68 75 73 75 64 6f 78 69 } //1 nakahusudoxi
		$a_81_4 = {62 69 7a 61 72 65 64 75 6c 69 } //1 bizareduli
		$a_81_5 = {63 61 76 75 77 6f 78 65 67 75 66 69 79 69 70 61 76 69 7a 65 73 } //1 cavuwoxegufiyipavizes
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=7
 
}