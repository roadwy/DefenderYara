
rule Trojan_BAT_KeyLogger_MVA_MTB{
	meta:
		description = "Trojan:BAT/KeyLogger.MVA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 69 73 63 6f 72 64 20 4b 65 79 6c 6f 67 67 65 72 2e 70 64 62 } //2 Discord Keylogger.pdb
		$a_01_1 = {48 6f 6f 74 4b 65 79 73 } //1 HootKeys
		$a_01_2 = {77 65 62 68 6f 6f 6b 73 74 61 72 74 } //1 webhookstart
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}