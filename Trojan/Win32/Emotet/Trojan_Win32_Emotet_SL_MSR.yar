
rule Trojan_Win32_Emotet_SL_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SL!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 69 6e 61 72 79 32 43 2b 2b 32 31 31 31 33 32 35 31 32 30 30 38 5c 52 65 6c 65 61 73 65 5c 42 69 6e 61 72 79 32 43 2b 2b 2e 70 64 62 } //01 00  Binary2C++211132512008\Release\Binary2C++.pdb
		$a_01_1 = {54 61 72 67 65 74 20 66 69 6c 65 20 69 73 20 77 72 69 74 74 65 6e } //01 00  Target file is written
		$a_01_2 = {63 76 66 47 62 7a 78 44 53 77 4b 6c 6d 70 53 78 63 5a 77 41 } //00 00  cvfGbzxDSwKlmpSxcZwA
	condition:
		any of ($a_*)
 
}