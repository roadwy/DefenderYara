
rule PWS_Win32_Banker_M{
	meta:
		description = "PWS:Win32/Banker.M,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 61 6e 74 61 6e 64 65 72 } //01 00  Santander
		$a_01_1 = {6b 65 79 32 30 31 30 } //01 00  key2010
		$a_00_2 = {8b 00 80 78 57 01 75 05 } //01 00 
		$a_01_3 = {67 6f 20 64 6f 20 69 54 6f 6b 65 6e 20 69 6e 76 61 6c 69 64 6f 2e } //02 00  go do iToken invalido.
		$a_03_4 = {35 ae ca 7b c3 ff 25 90 01 04 8b c0 53 33 db 6a 00 e8 ee ff ff ff 83 f8 07 75 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}