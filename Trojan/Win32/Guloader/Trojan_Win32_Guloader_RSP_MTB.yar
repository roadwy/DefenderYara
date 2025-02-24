
rule Trojan_Win32_GuLoader_RSP_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 00 6f 00 72 00 65 00 6f 00 67 00 72 00 61 00 66 00 65 00 72 00 65 00 6e 00 64 00 65 00 73 00 } //1 Koreograferendes
		$a_01_1 = {4b 00 61 00 6c 00 69 00 62 00 65 00 72 00 62 00 6f 00 72 00 } //1 Kaliberbor
		$a_01_2 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 56 00 65 00 6b 00 73 00 6c 00 65 00 6e 00 64 00 65 00 73 00 } //1 Software\Vekslendes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_GuLoader_RSP_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 75 6e 70 72 6f 73 65 6c 79 74 65 5c 62 65 73 70 61 72 65 6c 73 65 73 } //1 \unproselyte\besparelses
		$a_81_1 = {36 5c 50 72 65 66 69 67 75 72 65 2e 65 6d 75 } //1 6\Prefigure.emu
		$a_81_2 = {5c 73 74 65 6d 6d 65 73 70 69 6c 64 73 6b 61 6d 70 61 67 6e 65 73 2e 75 6e 61 } //1 \stemmespildskampagnes.una
		$a_81_3 = {65 6e 74 69 74 6c 65 20 76 72 64 69 66 75 6c 64 65 73 20 61 6e 61 6c 65 } //1 entitle vrdifuldes anale
		$a_81_4 = {62 69 73 68 6f 70 72 69 63 73 20 73 74 61 6c 61 67 6d 69 74 74 65 72 6e 65 } //1 bishoprics stalagmitterne
		$a_81_5 = {6d 65 6c 6c 65 6d 74 65 6b 73 74 65 6e 2e 65 78 65 } //1 mellemteksten.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}