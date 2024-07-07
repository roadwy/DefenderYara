
rule Trojan_Win32_Valden_D{
	meta:
		description = "Trojan:Win32/Valden.D,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 07 00 09 00 00 "
		
	strings :
		$a_00_0 = {2f 70 2f 73 65 72 76 65 72 } //1 /p/server
		$a_00_1 = {64 61 74 61 3d 69 6e 66 6f 26 62 61 6e 6b 3d 32 26 75 73 65 72 } //1 data=info&bank=2&user
		$a_00_2 = {66 6f 72 6d 53 69 63 72 65 64 69 49 6e 74 65 72 6e 65 74 22 20 6d 65 74 68 6f 64 3d 22 50 4f 53 54 22 } //1 formSicrediInternet" method="POST"
		$a_00_3 = {73 61 6e 74 61 6e 64 65 72 6e 65 74 69 62 65 2e 63 6f 6d 2e 62 72 2f 74 6f 70 6f 73 2f 49 42 50 4a 5f 54 6f 70 6f 2e 61 73 70 } //1 santandernetibe.com.br/topos/IBPJ_Topo.asp
		$a_00_4 = {62 61 6e 63 6f 62 72 61 73 69 6c 2e 63 6f 6d 2e 62 72 2f 61 61 70 66 2f } //1 bancobrasil.com.br/aapf/
		$a_00_5 = {68 73 62 63 2e 75 6e 69 61 6f 64 65 62 61 6e 63 6f 73 2e 6e 65 74 } //1 hsbc.uniaodebancos.net
		$a_00_6 = {73 69 63 72 65 64 69 2e 63 6f 6d 2e 62 72 2f 77 65 62 73 69 74 65 73 69 63 72 65 64 69 2f } //1 sicredi.com.br/websitesicredi/
		$a_01_7 = {c1 e0 08 0b c1 0f b6 8d 9e ff 00 00 c1 e0 08 0b c1 0f b6 8d 9f ff 00 00 c1 e0 08 6a 04 89 5d 94 0b c1 5f eb 64 } //3
		$a_01_8 = {81 6d fc 47 86 c8 61 03 f1 33 f7 03 c6 8b f0 c1 ee 05 8b f8 c1 e7 04 33 f7 8b 7d fc c1 ef 0b 83 e7 03 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3) >=7
 
}