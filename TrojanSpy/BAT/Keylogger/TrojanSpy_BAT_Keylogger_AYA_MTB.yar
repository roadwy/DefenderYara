
rule TrojanSpy_BAT_Keylogger_AYA_MTB{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 00 68 00 65 00 20 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 68 00 61 00 73 00 20 00 73 00 74 00 61 00 72 00 74 00 65 00 64 00 2c 00 20 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 69 00 6e 00 66 00 6f 00 72 00 6d 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 } //2 The logger has started, computer information:
		$a_00_1 = {69 00 2d 00 43 00 75 00 65 00 20 00 4c 00 6f 00 67 00 69 00 6e 00 } //1 i-Cue Login
		$a_01_2 = {4b 65 79 52 65 61 64 65 72 72 } //1 KeyReaderr
		$a_01_3 = {49 6e 73 74 61 6c 6c 50 52 47 } //1 InstallPRG
		$a_01_4 = {49 6e 66 6f 53 65 6e 64 65 72 5f 54 69 63 6b } //1 InfoSender_Tick
		$a_01_5 = {68 69 64 65 45 76 65 72 79 74 68 69 6e 67 } //1 hideEverything
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}