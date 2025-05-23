
rule MonitoringTool_MSIL_KBotRat{
	meta:
		description = "MonitoringTool:MSIL/KBotRat,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 2e 00 70 00 68 00 70 00 } //1 /command.php
		$a_01_1 = {7b 00 22 00 76 00 69 00 63 00 6e 00 61 00 6d 00 65 00 22 00 3a 00 22 00 28 00 2e 00 2a 00 } //1 {"vicname":"(.*
		$a_01_2 = {2f 00 73 00 75 00 70 00 6c 00 6f 00 61 00 64 00 2e 00 70 00 68 00 70 00 } //1 /supload.php
		$a_01_3 = {5c 00 53 00 74 00 75 00 62 00 2e 00 65 00 78 00 65 00 } //1 \Stub.exe
		$a_01_4 = {44 00 6f 00 6e 00 65 00 20 00 21 00 20 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 20 00 69 00 6e 00 20 00 3a 00 } //1 Done ! Create Server in :
		$a_01_5 = {6b 00 42 00 6f 00 74 00 43 00 6c 00 69 00 65 00 6e 00 74 00 } //1 kBotClient
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}