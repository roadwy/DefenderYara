
rule TrojanSpy_BAT_Keylogger_AI{
	meta:
		description = "TrojanSpy:BAT/Keylogger.AI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 74 6f 70 74 68 65 73 65 6c 66 70 72 6f 74 65 63 74 69 6f 6e 69 6e 6e 61 6d 65 6f 66 67 6f 64 65 } //stoptheselfprotectioninnameofgode  01 00 
		$a_80_1 = {5b 52 43 54 52 4c 41 50 50 53 5d } //[RCTRLAPPS]  01 00 
		$a_80_2 = {73 65 74 20 6b 65 79 62 6f 61 72 64 20 68 6f 6f 6b } //set keyboard hook  00 00 
	condition:
		any of ($a_*)
 
}