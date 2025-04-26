
rule TrojanSpy_Win32_Bancos_AHT{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHT,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {41 43 41 4f 3d 61 64 64 73 65 6e 68 61 73 } //1 ACAO=addsenhas
		$a_01_1 = {2f 46 65 72 72 61 72 69 2e 61 73 70 78 } //1 /Ferrari.aspx
		$a_01_2 = {2f 53 61 6e 74 61 6e 61 2e 61 73 70 78 } //1 /Santana.aspx
		$a_01_3 = {67 62 70 73 76 73 2e 64 6c 6c } //1 gbpsvs.dll
		$a_01_4 = {74 78 74 53 65 6e 68 61 54 6f 6b 65 6e } //1 txtSenhaToken
		$a_01_5 = {61 00 6c 00 65 00 72 00 74 00 28 00 22 00 53 00 65 00 6e 00 68 00 61 00 } //1 alert("Senha
		$a_01_6 = {3b 7d ec 7d 03 47 eb 05 bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e4 3b 5d e8 7f 0b 81 c3 ff 00 00 00 2b 5d e8 } //1
		$a_01_7 = {5c 5f 67 62 69 65 68 61 62 6e 2e 70 61 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}