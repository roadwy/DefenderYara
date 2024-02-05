
rule TrojanSpy_Win32_Bancos_YW{
	meta:
		description = "TrojanSpy:Win32/Bancos.YW,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 65 6e 68 61 20 43 61 72 74 61 6f 2e 2e 2e 2e 2e 3a 20 } //02 00 
		$a_01_1 = {43 6f 6d 70 6f 6e 65 6e 74 65 20 64 65 20 53 65 67 75 72 61 6e } //02 00 
		$a_01_2 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 } //01 00 
		$a_01_3 = {49 6d 61 67 65 35 32 43 6c 69 63 6b } //00 00 
	condition:
		any of ($a_*)
 
}