
rule TrojanSpy_Win32_Bancos_ND_dll{
	meta:
		description = "TrojanSpy:Win32/Bancos.ND!dll,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 48 74 2b 66 55 70 43 52 55 74 4d 55 46 42 57 58 6c 78 63 5a 57 6c 6c 62 47 35 76 6c 62 6d 35 65 37 69 2f 74 72 2f 41 30 5a 44 51 31 74 48 63 34 36 4c 6f 33 74 2f 6b 35 4f 71 32 37 41 45 42 30 77 54 2f 43 78 4d 45 44 51 34 5a 37 4f 4d 3d } //01 00  bHt+fUpCRUtMUFBWXlxcZWllbG5vlbm5e7i/tr/A0ZDQ1tHc46Lo3t/k5Oq27AEB0wT/CxMEDQ4Z7OM=
		$a_01_1 = {b8 34 8e 49 00 e8 e2 4d fd ff 8b 85 10 fe ff ff e8 07 f5 ff ff 68 b8 0b 00 00 e8 45 df f6 ff 8b 45 f8 e8 e5 bf f6 ff 50 e8 27 dd f6 ff } //00 00 
	condition:
		any of ($a_*)
 
}