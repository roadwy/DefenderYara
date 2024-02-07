
rule TrojanSpy_Win32_Banker_ANQ{
	meta:
		description = "TrojanSpy:Win32/Banker.ANQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 6c 74 3d 22 49 6e 66 6f 72 6d 65 20 73 75 61 20 73 65 6e 68 61 20 64 65 20 36 20 64 c3 ad 67 69 74 6f 73 2e 22 } //01 00 
		$a_01_1 = {53 6e 61 6d 65 3d 74 6f 6b 65 6e 44 75 70 6c 6f 43 6c 69 71 75 65 3e 20 3c 49 4e 50 55 54 20 74 79 70 65 3d 68 69 64 64 65 6e 20 6e 61 6d 65 3d 63 6f 64 69 67 6f 54 72 61 6e 73 61 63 61 6f 3e } //01 00  Sname=tokenDuploClique> <INPUT type=hidden name=codigoTransacao>
		$a_01_2 = {3d 74 79 70 65 3d 22 70 61 73 73 77 6f 72 64 22 20 63 6c 61 73 73 3d 22 63 61 6d 70 6f 22 20 73 69 7a 65 3d 22 36 22 20 6d 61 78 6c 65 6e 67 74 68 3d 22 36 22 20 2f 3e 26 6e 62 73 70 3b } //01 00  =type="password" class="campo" size="6" maxlength="6" />&nbsp;
		$a_01_3 = {45 73 73 61 20 76 61 6c 69 64 61 26 23 32 33 31 3b 26 23 32 32 37 3b 6f 20 76 61 6c 65 72 26 23 32 32 35 3b 20 70 61 72 61 20 61 73 20 64 65 6d 61 69 73 20 6f 70 65 72 61 26 23 32 33 31 } //01 00  Essa valida&#231;&#227;o valer&#225; para as demais opera&#231
		$a_01_4 = {6a 61 76 61 73 63 72 69 70 74 3a 61 63 65 73 73 61 50 61 67 69 6e 61 28 22 73 65 6c 65 63 69 6f 6e 61 5f 69 6e 76 65 73 74 69 6d 65 6e 74 6f 2e 70 72 6f 63 65 73 73 61 22 29 } //00 00  javascript:acessaPagina("seleciona_investimento.processa")
	condition:
		any of ($a_*)
 
}