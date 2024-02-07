
rule Trojan_Win32_Bredo_PA_MTB{
	meta:
		description = "Trojan:Win32/Bredo.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c2 10 00 b9 90 01 04 33 c0 8a 90 90 90 01 04 32 d1 41 81 e1 ff 00 00 80 88 54 04 90 01 01 79 90 01 01 49 81 c9 00 ff ff ff 41 40 83 f8 90 01 01 7c 90 00 } //01 00 
		$a_00_1 = {68 00 61 00 68 00 61 00 68 00 61 00 2e 00 65 00 78 00 65 00 } //00 00  hahaha.exe
	condition:
		any of ($a_*)
 
}