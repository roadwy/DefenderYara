
rule Backdoor_Win32_PornDialer_H{
	meta:
		description = "Backdoor:Win32/PornDialer.H,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 0a 00 "
		
	strings :
		$a_00_0 = {52 61 73 53 65 74 45 6e 74 72 79 44 69 61 6c 50 61 72 61 6d 73 41 } //01 00  RasSetEntryDialParamsA
		$a_01_1 = {76 65 72 69 66 69 63 61 74 6f 20 75 6e 20 65 72 72 6f 72 65 2e 20 4c 27 61 70 70 6c 69 63 61 7a 69 6f 6e 65 20 56 65 72 72 } //01 00  verificato un errore. L'applicazione Verr
		$a_01_2 = {51 55 45 4c 4c 4f 20 43 48 45 20 54 49 20 50 49 41 43 45 } //01 00  QUELLO CHE TI PIACE
		$a_01_3 = {53 54 4f 50 2d 50 45 44 4f 46 49 4c 49 41 } //01 00  STOP-PEDOFILIA
		$a_01_4 = {4d 4f 44 45 4d } //01 00  MODEM
		$a_01_5 = {41 70 65 72 74 75 72 61 20 50 6f 72 74 61 2e 2e 2e } //01 00  Apertura Porta...
		$a_01_6 = {43 6f 6e 6e 65 73 73 69 6f 6e 65 20 44 65 76 69 63 65 2e 2e 2e } //01 00  Connessione Device...
		$a_01_7 = {43 4f 4e 4e 45 53 53 4f 21 } //0a 00  CONNESSO!
		$a_02_8 = {83 f8 05 7f 36 74 2d 2b c7 74 22 48 74 18 48 74 0e 48 0f 85 8d 00 00 00 68 90 01 02 40 00 eb 7f 68 90 01 02 40 00 eb 78 68 90 01 02 40 00 eb 71 68 90 01 02 40 00 eb 6a 68 90 01 02 40 00 eb 63 83 e8 06 74 59 2d fa 1f 00 00 74 0a 48 75 5b 68 90 01 02 40 00 eb 4d 68 90 01 02 40 00 8b ce e8 90 01 04 6a 01 58 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}