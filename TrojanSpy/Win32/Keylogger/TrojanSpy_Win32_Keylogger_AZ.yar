
rule TrojanSpy_Win32_Keylogger_AZ{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 09 2e 65 78 65 90 02 09 25 32 30 00 47 45 54 20 2f 6c 6f 61 64 64 64 2e 70 68 70 90 00 } //01 00 
		$a_00_1 = {6b 65 79 6c 6f 67 67 65 72 } //00 00  keylogger
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Keylogger_AZ_2{
	meta:
		description = "TrojanSpy:Win32/Keylogger.AZ,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 75 61 6e 65 73 6b 65 79 6c 6f 67 67 65 72 2e 70 6c } //02 00  .uaneskeylogger.pl
		$a_01_1 = {2f 75 70 64 2e 70 68 70 3f 64 61 74 61 3d 00 26 73 69 64 3d 00 } //02 00 
		$a_01_2 = {2f 6c 6f 61 64 64 64 2e 70 68 70 3f 64 61 74 61 3d 00 26 73 69 64 3d 00 } //01 00 
		$a_01_3 = {26 70 61 67 65 00 26 6c 6f 67 69 6e 70 61 73 73 77 6f 72 64 3d 00 } //01 00  瀦条e氦杯湩慰獳潷摲=
		$a_01_4 = {5c 52 75 6e 00 63 73 72 73 2e 65 78 65 00 } //01 00 
		$a_01_5 = {5c 52 75 6e 00 63 72 73 72 2e 65 78 65 00 } //01 00 
		$a_01_6 = {5c 52 75 6e 00 63 73 72 72 73 2e 65 78 65 00 } //01 00 
		$a_01_7 = {54 69 62 69 61 43 6c 69 65 6e 74 00 } //00 00  楔楢䍡楬湥t
	condition:
		any of ($a_*)
 
}