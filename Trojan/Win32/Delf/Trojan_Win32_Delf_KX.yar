
rule Trojan_Win32_Delf_KX{
	meta:
		description = "Trojan:Win32/Delf.KX,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 3a 5c 33 36 30 5c 33 36 30 53 61 66 65 2e 72 65 67 } //01 00  d:\360\360Safe.reg
		$a_01_1 = {64 3a 5c 33 36 30 53 61 66 65 2e 72 65 67 } //01 00  d:\360Safe.reg
		$a_01_2 = {64 3a 5c 33 36 30 2e 72 65 67 } //05 00  d:\360.reg
		$a_03_3 = {68 c8 00 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 c8 00 00 00 e8 90 01 02 ff ff e8 90 01 02 ff ff 68 90 01 02 40 00 e8 90 01 02 ff ff 6a 64 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}