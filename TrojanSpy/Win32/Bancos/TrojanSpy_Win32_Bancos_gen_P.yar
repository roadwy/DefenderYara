
rule TrojanSpy_Win32_Bancos_gen_P{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4e 4b 4a 41 4a 53 59 45 52 55 59 4f 49 55 4f 53 44 4a 4b 46 48 4d 56 4e 53 44 4a 46 48 4a 4b 53 44 4a 46 4b 4c 53 4a 46 44 48 44 53 45 52 39 } //01 00  CNKJAJSYERUYOIUOSDJKFHMVNSDJFHJKSDJFKLSJFDHDSER9
		$a_02_1 = {8b d8 ba 02 00 00 80 8b c3 e8 90 01 04 8d 55 90 01 01 b8 90 01 04 e8 90 01 04 8b 55 90 01 01 33 c9 8b c3 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}