
rule TrojanSpy_BAT_Keylogger_SSD_MTB{
	meta:
		description = "TrojanSpy:BAT/Keylogger.SSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 69 6e 6c 6f 67 67 65 72 48 65 6c 70 65 72 73 } //1 PinloggerHelpers
		$a_00_1 = {47 00 61 00 6c 00 61 00 78 00 79 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 56 00 33 00 20 00 53 00 74 00 6f 00 6c 00 65 00 6e 00 20 00 50 00 61 00 73 00 73 00 65 00 73 00 } //1 Galaxy Logger V3 Stolen Passes
		$a_00_2 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 33 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 20 00 26 00 20 00 64 00 65 00 6c 00 } //1 /c ping -n 3 127.0.0.1 > nul & del
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}