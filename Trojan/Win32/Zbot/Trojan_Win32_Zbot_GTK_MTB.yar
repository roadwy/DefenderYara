
rule Trojan_Win32_Zbot_GTK_MTB{
	meta:
		description = "Trojan:Win32/Zbot.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {67 6c 6f 77 65 72 2e 65 78 65 } //glower.exe  1
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_01_2 = {44 6c 6c 46 75 6e 63 74 69 6f 6e 43 61 6c 6c } //1 DllFunctionCall
		$a_01_3 = {5a 50 4f 57 54 57 5a 48 46 44 54 50 54 51 59 42 51 42 75 72 67 68 49 4f } //1 ZPOWTWZHFDTPTQYBQBurghIO
		$a_01_4 = {51 42 75 72 67 68 49 4f 44 41 47 44 4b 5a } //1 QBurghIODAGDKZ
		$a_01_5 = {44 4b 5a 50 4f 57 54 57 5e 48 46 44 57 50 54 51 } //1 DKZPOWTW^HFDWPTQ
		$a_01_6 = {47 44 54 50 54 51 59 42 51 42 75 72 67 68 49 4f 44 41 47 44 } //1 GDTPTQYBQBurghIODAGD
	condition:
		((#a_80_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}