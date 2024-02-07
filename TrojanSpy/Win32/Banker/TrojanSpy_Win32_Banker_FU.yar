
rule TrojanSpy_Win32_Banker_FU{
	meta:
		description = "TrojanSpy:Win32/Banker.FU,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2c 70 61 73 73 6f 75 20 6e 61 20 59 2d 2d 4f 2d 2d 55 20 54 2d 2d 55 2d 2d 42 2d 2d 45 20 20 65 20 65 6e 76 69 6f 75 2d 6c 68 65 20 75 6d 20 56 69 64 65 6f 20 61 6e 69 6d 61 64 6f 20 70 61 72 61 20 76 6f 63 } //01 00  ,passou na Y--O--U T--U--B--E  e enviou-lhe um Video animado para voc
		$a_01_1 = {43 61 73 6f 20 6f 20 6c 69 6e 6b 20 6e 61 6f 20 66 69 71 75 65 20 63 6c 69 63 61 76 65 6c 2c 20 63 6f 70 69 65 20 65 20 63 6f 6c 65 20 6e 6f 20 73 65 75 20 6e 61 76 65 67 61 64 6f 72 2e } //01 00  Caso o link nao fique clicavel, copie e cole no seu navegador.
		$a_01_2 = {40 74 65 72 72 61 2e 63 6f 6d 2e 62 72 } //01 00  @terra.com.br
		$a_01_3 = {63 3a 5c 4d 53 4e 5f 45 4e 56 49 41 2e 6c 6f 67 } //01 00  c:\MSN_ENVIA.log
		$a_01_4 = {54 46 4f 52 4d 31 } //01 00  TFORM1
		$a_01_5 = {3d 4d 53 4e 5f 45 4e 56 49 41 } //01 00  =MSN_ENVIA
		$a_01_6 = {4d 65 73 73 65 6e 67 65 72 41 50 49 45 76 65 6e 74 73 } //00 00  MessengerAPIEvents
	condition:
		any of ($a_*)
 
}