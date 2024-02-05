
rule Trojan_Win32_Chymine_A{
	meta:
		description = "Trojan:Win32/Chymine.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 f1 17 83 c0 02 66 89 0a 8b d0 66 8b 08 66 3b ce 75 ed } //01 00 
		$a_01_1 = {68 42 7c 00 b5 56 e8 } //01 00 
		$a_00_2 = {52 00 4f 00 4f 00 54 00 5c 00 43 00 49 00 4d 00 56 00 32 00 } //01 00 
		$a_00_3 = {25 00 73 00 20 00 73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 2c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 52 00 75 00 6e 00 44 00 4c 00 4c 00 41 00 20 00 22 00 25 00 73 00 22 00 } //04 00 
		$a_03_4 = {68 70 bf c4 5f 68 90 01 04 c6 45 e0 68 c6 45 e1 74 c6 45 e2 74 c6 45 e3 70 c6 45 e4 3a c6 45 e5 2f c6 45 e6 2f c6 45 e7 32 c6 45 e8 30 c6 45 e9 35 c6 45 ea 2e c6 45 eb 32 c6 45 ec 30 c6 45 ed 39 c6 45 ee 2e c6 45 ef 31 c6 45 f0 37 c6 45 f1 31 c6 45 f2 2e c6 45 f3 31 c6 45 f4 31 c6 45 f5 39 c6 45 f6 2f c6 45 f7 62 c6 45 f8 69 c6 45 f9 6e c6 45 fa 2e c6 45 fb 65 c6 45 fc 78 c6 45 fd 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}