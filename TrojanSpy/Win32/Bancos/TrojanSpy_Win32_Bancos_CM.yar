
rule TrojanSpy_Win32_Bancos_CM{
	meta:
		description = "TrojanSpy:Win32/Bancos.CM,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 07 00 00 04 00 "
		
	strings :
		$a_01_0 = {c1 ed 0f 33 dd 03 c3 03 d8 8b e8 c1 e5 0b 33 c5 4f 75 a5 } //02 00 
		$a_01_1 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c 72 66 6b 73 61 64 76 6e 71 69 6e 64 79 77 33 6e 65 72 61 73 64 66 } //02 00  =_NextPart_2relrfksadvnqindyw3nerasdf
		$a_01_2 = {73 65 6e 68 61 43 61 72 74 61 6f } //02 00  senhaCartao
		$a_01_3 = {6a 61 76 61 73 63 72 69 70 74 3a 56 61 6c 69 64 61 53 65 6e 68 61 28 } //01 00  javascript:ValidaSenha(
		$a_01_4 = {6d 61 64 43 6f 64 65 48 6f 6f 6b } //01 00  madCodeHook
		$a_01_5 = {53 65 6e 64 56 61 6c 43 6c 69 63 6b 28 } //01 00  SendValClick(
		$a_01_6 = {53 65 6e 68 61 20 36 20 44 69 67 69 74 6f 73 3a } //00 00  Senha 6 Digitos:
	condition:
		any of ($a_*)
 
}