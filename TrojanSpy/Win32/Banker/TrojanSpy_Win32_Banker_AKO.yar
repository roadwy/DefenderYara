
rule TrojanSpy_Win32_Banker_AKO{
	meta:
		description = "TrojanSpy:Win32/Banker.AKO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 78 74 53 65 6e 68 61 54 6f 6b 65 6e 2e 76 61 6c 75 65 3d } //01 00  txtSenhaToken.value=
		$a_01_1 = {54 69 6d 65 5f 44 65 6e 74 72 6f 5f 70 65 67 61 5f 55 73 75 61 72 69 6f 54 69 6d 65 72 } //01 00  Time_Dentro_pega_UsuarioTimer
		$a_01_2 = {54 49 4d 45 5f 4c 45 5f 53 45 52 56 49 44 4f 52 } //01 00  TIME_LE_SERVIDOR
		$a_01_3 = {54 69 6d 65 50 65 67 61 42 6f 74 61 6f 54 69 6d 65 72 } //00 00  TimePegaBotaoTimer
		$a_00_4 = {5d 04 00 } //00 06 
	condition:
		any of ($a_*)
 
}