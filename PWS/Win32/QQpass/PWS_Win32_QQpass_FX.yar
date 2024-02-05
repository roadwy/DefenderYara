
rule PWS_Win32_QQpass_FX{
	meta:
		description = "PWS:Win32/QQpass.FX,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 49 6e 74 65 72 6e 61 6c 2e 65 78 65 } //01 00 
		$a_01_1 = {5c 56 6f 64 43 61 74 63 68 } //01 00 
		$a_01_2 = {da d1 b6 51 51 2e 6c 6e 6b 00 } //01 00 
		$a_01_3 = {75 51 51 32 30 31 32 56 65 72 73 69 6f 6e } //01 00 
		$a_01_4 = {4e 6f 44 72 69 76 65 73 00 00 00 00 52 65 73 74 72 69 63 74 52 75 6e 00 00 00 00 00 4e 6f 4e 65 74 43 6f 6e 6e 65 63 74 44 69 73 63 6f 6e 6e 65 63 74 00 } //00 00 
	condition:
		any of ($a_*)
 
}