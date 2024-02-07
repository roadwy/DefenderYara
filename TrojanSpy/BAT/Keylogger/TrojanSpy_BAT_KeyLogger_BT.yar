
rule TrojanSpy_BAT_KeyLogger_BT{
	meta:
		description = "TrojanSpy:BAT/KeyLogger.BT,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  explorer.Resources
		$a_01_1 = {40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //01 00  @gmail.com
		$a_01_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //01 00  GetAsyncKeyState
		$a_01_3 = {6b 65 79 62 64 5f 65 76 65 6e 74 } //00 00  keybd_event
	condition:
		any of ($a_*)
 
}