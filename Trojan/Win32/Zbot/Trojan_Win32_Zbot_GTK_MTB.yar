
rule Trojan_Win32_Zbot_GTK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {67 6c 6f 77 65 72 2e 65 78 65 } //glower.exe  01 00 
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_2 = {44 6c 6c 46 75 6e 63 74 69 6f 6e 43 61 6c 6c } //01 00  DllFunctionCall
		$a_01_3 = {5a 50 4f 57 54 57 5a 48 46 44 54 50 54 51 59 42 51 42 75 72 67 68 49 4f } //01 00  ZPOWTWZHFDTPTQYBQBurghIO
		$a_01_4 = {51 42 75 72 67 68 49 4f 44 41 47 44 4b 5a } //01 00  QBurghIODAGDKZ
		$a_01_5 = {44 4b 5a 50 4f 57 54 57 5e 48 46 44 57 50 54 51 } //01 00  DKZPOWTW^HFDWPTQ
		$a_01_6 = {47 44 54 50 54 51 59 42 51 42 75 72 67 68 49 4f 44 41 47 44 } //00 00  GDTPTQYBQBurghIODAGD
	condition:
		any of ($a_*)
 
}