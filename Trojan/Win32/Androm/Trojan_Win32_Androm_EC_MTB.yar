
rule Trojan_Win32_Androm_EC_MTB{
	meta:
		description = "Trojan:Win32/Androm.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 74 00 69 00 6e 00 61 00 65 00 30 00 2e 00 65 00 78 00 65 00 } //01 00  Retinae0.exe
		$a_01_1 = {46 00 6c 00 6f 00 6b 00 69 00 74 00 65 00 33 00 } //01 00  Flokite3
		$a_01_2 = {49 74 75 6d 6b 61 6c 61 31 } //01 00  Itumkala1
		$a_01_3 = {5a 61 6e 7a 69 62 61 72 69 73 34 } //01 00  Zanzibaris4
		$a_01_4 = {43 72 65 61 74 65 54 69 6d 65 72 51 75 65 75 65 54 69 6d 65 72 } //01 00  CreateTimerQueueTimer
		$a_01_5 = {53 6c 65 65 70 45 78 } //01 00  SleepEx
		$a_01_6 = {52 65 61 64 45 76 65 6e 74 4c 6f 67 41 } //00 00  ReadEventLogA
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Androm_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Androm.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 65 4f 63 75 6c 74 6f 5f 44 6f 63 75 6d 65 6e 74 43 6f 6d 70 6c 65 74 65 } //01 00  ieOculto_DocumentComplete
		$a_01_1 = {63 68 65 63 61 72 62 72 6f 77 73 65 72 } //01 00  checarbrowser
		$a_01_2 = {45 00 73 00 63 00 72 00 69 00 74 00 6f 00 72 00 69 00 6f 00 5c 00 6d 00 6f 00 64 00 69 00 66 00 69 00 63 00 61 00 20 00 41 00 67 00 6f 00 73 00 74 00 6f 00 32 00 } //01 00  Escritorio\modifica Agosto2
		$a_01_3 = {45 00 78 00 65 00 63 00 51 00 75 00 65 00 72 00 79 00 } //01 00  ExecQuery
		$a_01_4 = {2d 43 30 30 30 2d 52 65 63 33 32 } //01 00  -C000-Rec32
		$a_01_5 = {69 65 52 65 74 75 72 6e 53 6f 75 72 63 65 53 65 72 76 65 72 } //00 00  ieReturnSourceServer
	condition:
		any of ($a_*)
 
}