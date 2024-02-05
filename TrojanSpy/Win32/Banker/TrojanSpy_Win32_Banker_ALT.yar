
rule TrojanSpy_Win32_Banker_ALT{
	meta:
		description = "TrojanSpy:Win32/Banker.ALT,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {4a 47 6b 32 31 67 47 } //02 00 
		$a_01_1 = {55 70 64 61 74 65 72 4c 6f 67 54 65 63 6b } //01 00 
		$a_01_2 = {48 4a 49 38 2e 7a 69 70 } //01 00 
		$a_01_3 = {49 36 48 38 2e 65 78 65 } //02 00 
		$a_03_4 = {35 ae ca 7b c3 ff 25 90 01 04 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 90 00 } //00 00 
		$a_00_5 = {5d 04 00 00 87 10 } //03 80 
	condition:
		any of ($a_*)
 
}