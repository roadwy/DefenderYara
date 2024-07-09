
rule TrojanSpy_Win32_Banker_AEE{
	meta:
		description = "TrojanSpy:Win32/Banker.AEE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {67 00 62 00 69 00 65 00 68 00 6c 00 69 00 62 00 } //1 gbiehlib
		$a_02_1 = {6d 61 69 6c 61 67 65 6e 74 [0-1b] 68 65 6c 6f 6e 61 6d 65 [0-1b] 75 73 65 65 68 6c 6f } //1
		$a_01_2 = {0e 54 4b 65 79 50 72 65 73 73 45 76 65 6e 74 } //1
		$a_01_3 = {56 4e 43 53 65 72 76 65 72 57 69 6e 33 32 00 } //1
		$a_00_4 = {63 61 6d 69 6e 68 6f } //1 caminho
		$a_00_5 = {73 65 6e 68 61 } //1 senha
		$a_00_6 = {63 6f 6d 70 75 74 61 64 6f 72 } //1 computador
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}