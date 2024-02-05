
rule TrojanSpy_Win32_Bancos_AMJ{
	meta:
		description = "TrojanSpy:Win32/Bancos.AMJ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 5c 70 61 79 6c 6f 61 64 5c 70 61 79 6c 6f 61 64 2e 78 38 36 2e 70 64 62 } //01 00 
		$a_81_1 = {4d 6f 64 69 66 69 63 61 20 64 65 6c 20 50 49 4e } //02 00 
		$a_01_2 = {8b f2 8b c8 2b f0 8b d7 8a 1c 0e 32 5d 0c 88 19 41 4a 75 f4 } //00 00 
		$a_00_3 = {87 10 } //00 00 
	condition:
		any of ($a_*)
 
}