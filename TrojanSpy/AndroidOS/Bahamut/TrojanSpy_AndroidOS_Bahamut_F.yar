
rule TrojanSpy_AndroidOS_Bahamut_F{
	meta:
		description = "TrojanSpy:AndroidOS/Bahamut.F,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 72 67 61 2f 6d 69 6d 65 2f 42 6f 6f 74 43 6f 6d 70 6c 65 74 65 52 65 63 65 69 76 65 72 3b } //1 Lorga/mime/BootCompleteReceiver;
		$a_01_1 = {2f 53 68 65 6c 6c 53 65 72 76 69 63 65 3b } //1 /ShellService;
		$a_01_2 = {74 69 74 65 70 65 72 66 6f 72 6d 61 6e 63 65 2e 63 6f 6d } //1 titeperformance.com
		$a_01_3 = {63 6f 6d 2e 61 74 2e 63 6f 64 65 72 2e 63 6f 6d 6d 61 6e 64 68 61 6e 64 6c 65 72 2e 4d 65 73 73 61 67 65 48 61 6e 64 6c 65 72 } //1 com.at.coder.commandhandler.MessageHandler
		$a_01_4 = {75 70 64 61 74 65 2e 6a 61 72 } //1 update.jar
		$a_01_5 = {5e 75 70 64 61 74 65 5b 61 2d 7a 41 2d 5a 30 2d 39 5f 5d 2a 5c 2e 6a 61 72 } //1 ^update[a-zA-Z0-9_]*\.jar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}