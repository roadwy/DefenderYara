
rule TrojanDropper_Win32_Delf_TF{
	meta:
		description = "TrojanDropper:Win32/Delf.TF,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {76 40 00 d6 07 66 c7 05 90 01 01 76 40 00 05 00 66 c7 05 90 01 01 76 40 00 19 00 66 c7 05 90 01 01 76 40 00 11 00 66 c7 05 90 01 01 76 40 00 00 00 66 c7 05 90 01 01 76 40 00 00 00 68 90 01 01 76 40 00 68 90 01 01 76 40 00 68 90 01 01 76 40 00 68 90 01 01 76 40 00 ff 35 6c 76 40 00 ff 35 70 76 40 00 90 00 } //01 00 
		$a_00_1 = {6c 6f 67 6f 78 2e 64 6c 6c 00 } //01 00 
		$a_00_2 = {6e 74 6c 61 70 69 2e 64 6c 6c 00 } //01 00 
		$a_00_3 = {6b 6e 72 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}