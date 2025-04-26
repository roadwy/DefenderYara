
rule TrojanSpy_Win32_Banker_MC{
	meta:
		description = "TrojanSpy:Win32/Banker.MC,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 20 43 68 61 76 65 20 64 65 20 53 65 67 75 72 61 6e } //1 o Chave de Seguran
		$a_01_1 = {3d 72 6f 62 69 6e 77 6f 6f 64 62 72 40 67 6d 61 69 6c 2e 63 6f 6d } //1 =robinwoodbr@gmail.com
		$a_01_2 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 49 6e 66 65 63 74 65 64 73 } //1 SELECT * FROM Infecteds
		$a_01_3 = {42 72 61 64 65 73 63 6f 20 2d 20 41 74 75 61 6c 69 7a 61 } //1 Bradesco - Atualiza
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}