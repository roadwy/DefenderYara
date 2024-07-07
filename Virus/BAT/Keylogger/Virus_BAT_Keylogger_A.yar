
rule Virus_BAT_Keylogger_A{
	meta:
		description = "Virus:BAT/Keylogger.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 4b 65 79 4c 6f 67 67 65 72 } //1 StartKeyLogger
		$a_01_1 = {53 74 61 72 74 52 65 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 69 63 65 } //1 StartReplicationService
		$a_01_2 = {53 65 6e 64 4d 61 69 6c } //1 SendMail
		$a_01_3 = {49 6e 66 65 63 74 45 58 45 } //1 InfectEXE
		$a_01_4 = {44 65 74 65 63 74 52 65 6d 6f 76 61 62 6c 65 44 72 69 76 65 } //1 DetectRemovableDrive
		$a_01_5 = {3c 00 2d 00 70 00 72 00 69 00 6e 00 74 00 20 00 73 00 63 00 72 00 65 00 65 00 6e 00 2d 00 3e 00 } //1 <-print screen->
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}