
rule TrojanSpy_Win32_Delf_DH{
	meta:
		description = "TrojanSpy:Win32/Delf.DH,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 ba e2 04 8b 45 90 01 01 e8 90 02 30 8b 08 ff 51 38 90 02 a0 66 ba e2 04 8b 45 90 1b 00 e8 90 00 } //01 00 
		$a_02_1 = {45 4d 61 69 6c 3a 90 02 18 53 65 72 76 90 00 } //01 00 
		$a_02_2 = {6e 6f 6d 65 90 02 18 74 65 78 74 6f 90 02 18 68 74 74 70 3a 2f 2f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}