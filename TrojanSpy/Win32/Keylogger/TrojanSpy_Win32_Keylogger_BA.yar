
rule TrojanSpy_Win32_Keylogger_BA{
	meta:
		description = "TrojanSpy:Win32/Keylogger.BA,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5c 64 61 74 61 5c 61 70 70 64 61 74 61 2e 64 6c 6c 90 02 09 5c 64 61 74 61 5c 61 70 70 64 61 74 61 2e 64 61 74 90 02 09 5c 6b 65 79 6c 6f 67 67 65 72 2e 64 6c 6c 90 02 09 5c 53 45 52 56 49 43 45 53 2e 45 58 45 90 02 09 6f 70 74 69 6f 6e 90 02 09 50 72 6f 74 65 63 74 69 6f 6e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}