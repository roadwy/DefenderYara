
rule TrojanSpy_Win32_Bancos_RG{
	meta:
		description = "TrojanSpy:Win32/Bancos.RG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 4e 65 78 74 50 61 72 74 5f 32 61 6c 74 72 66 6b } //01 00  _NextPart_2altrfk
		$a_01_1 = {2f 63 68 61 76 65 2e 74 78 74 } //01 00  /chave.txt
		$a_01_2 = {63 61 6d 70 6f 20 73 6f 6c 69 63 69 74 61 64 6f 2e } //01 00  campo solicitado.
		$a_01_3 = {53 65 6e 68 61 20 64 65 20 34 20 64 69 67 69 74 6f 73 } //00 00  Senha de 4 digitos
	condition:
		any of ($a_*)
 
}