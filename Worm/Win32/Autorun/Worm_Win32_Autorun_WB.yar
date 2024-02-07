
rule Worm_Win32_Autorun_WB{
	meta:
		description = "Worm:Win32/Autorun.WB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 75 00 70 00 64 00 61 00 74 00 65 00 2e 00 76 00 62 00 70 00 } //01 00  \update.vbp
		$a_01_1 = {3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 } //01 00  :\autorun.
		$a_01_2 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00 2e 00 20 00 52 00 65 00 73 00 65 00 72 00 76 00 61 00 64 00 6f 00 73 00 20 00 74 00 6f 00 64 00 6f 00 73 00 20 00 6c 00 6f 00 73 00 20 00 64 00 65 00 72 00 65 00 63 00 68 00 6f 00 73 00 2e 00 } //01 00  Microsoft Corporation. Reservados todos los derechos.
		$a_01_3 = {74 6d 72 43 65 6e 74 69 6e 65 6c 61 } //01 00  tmrCentinela
		$a_01_4 = {5f 43 3a 5c 57 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 69 65 66 72 61 6d 65 2e 6f 63 61 } //01 00  _C:\Windows\system32\ieframe.oca
		$a_01_5 = {74 6d 72 45 6c 69 6d 69 6e 61 72 } //01 00  tmrEliminar
		$a_01_6 = {69 6e 69 63 69 6f } //01 00  inicio
		$a_01_7 = {43 72 65 61 72 5f 41 75 74 6f 72 75 6e } //01 00  Crear_Autorun
		$a_01_8 = {43 6f 70 69 61 72 5f 41 75 74 6f 72 75 6e } //01 00  Copiar_Autorun
		$a_01_9 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //00 00  CreateToolhelp32Snapshot
	condition:
		any of ($a_*)
 
}