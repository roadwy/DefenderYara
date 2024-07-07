
rule TrojanSpy_BAT_KeyLogger_BR{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.BR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 61 00 64 00 4c 00 6f 00 67 00 73 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } //1 ReadLogsKeylogger
		$a_01_1 = {42 00 6f 00 74 00 6e 00 65 00 74 00 20 00 4f 00 66 00 66 00 6c 00 69 00 6e 00 65 00 } //1 Botnet Offline
		$a_01_2 = {65 00 6e 00 74 00 72 00 61 00 64 00 61 00 74 00 72 00 61 00 73 00 65 00 72 00 61 00 3d 00 68 00 69 00 64 00 61 00 64 00 26 00 6b 00 65 00 79 00 3d 00 } //1 entradatrasera=hidad&key=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}