
rule TrojanSpy_Win32_Bancos_AHR{
	meta:
		description = "TrojanSpy:Win32/Bancos.AHR,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 03 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6b 69 6c 6c 00 } //03 00 
		$a_01_1 = {2f 49 4d 20 69 65 78 70 6c 6f 72 65 2e 65 78 65 20 2f 46 } //01 00 
		$a_01_2 = {00 2b 20 50 43 4e 61 6d 65 20 2b 00 } //01 00 
		$a_01_3 = {00 70 72 61 71 75 65 6d 3d } //01 00 
		$a_01_4 = {4e 75 6d 65 72 6f 20 53 00 } //01 00 
		$a_01_5 = {73 6d 74 70 73 2e 75 6f 6c 2e 63 6f 6d 2e 62 72 } //00 00 
	condition:
		any of ($a_*)
 
}