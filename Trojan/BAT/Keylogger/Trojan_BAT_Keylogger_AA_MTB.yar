
rule Trojan_BAT_Keylogger_AA_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.AA!MTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 48 61 63 6b } //1 KeyHack
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 45 78 65 63 75 74 6f 72 } //1 KeyloggerExecutor
		$a_01_2 = {63 00 6f 00 73 00 74 00 75 00 72 00 61 00 2e 00 6b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 64 00 6c 00 6c 00 2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 } //1 costura.keylogger.dll.compressed
		$a_01_3 = {63 00 6f 00 73 00 74 00 75 00 72 00 61 00 2e 00 63 00 6f 00 73 00 74 00 75 00 72 00 61 00 2e 00 64 00 6c 00 6c 00 2e 00 63 00 6f 00 6d 00 70 00 72 00 65 00 73 00 73 00 65 00 64 00 } //1 costura.costura.dll.compressed
		$a_01_4 = {4b 65 79 6c 6f 67 67 65 72 43 6f 6e 66 69 67 } //1 KeyloggerConfig
		$a_01_5 = {53 74 61 72 74 4c 6f 67 67 69 6e 67 } //1 StartLogging
		$a_01_6 = {53 74 65 61 6d 53 65 72 76 69 63 65 2e 65 78 65 } //1 SteamService.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}